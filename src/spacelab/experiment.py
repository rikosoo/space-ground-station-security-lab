"""Experiment harness: runs trials, scores detections, aggregates statistics.

Protocol (one trial):

1. **Warm-up** - ``warmup_days`` of nominal operations with the engine in
   learning mode. Behavioural rules build their profiles here and emit nothing.
2. **Measurement** - ``measure_days`` of nominal operations with the attacks
   injected at staggered times. Attacks are separated by ``attack_spacing_h`` so
   that every alert can be attributed to exactly one of them.

Scoring definitions used throughout the paper:

* An alert is a **true positive** if at least one event in its evidence carries a
  non-benign ground-truth label; otherwise it is a **false positive**. Attribution
  therefore follows causality, not time proximity.
* **Time to detect (TTD)** for attack *A* is the first attributed alert's
  actionable timestamp minus the attack's first malicious action ``t0``. It
  includes the pipeline latency of the tier that produced the alert.
* **Time to contain (TTC)** is the first automated containment action on the
  attack's entity minus ``t0``.
* **Impact after containment** counts malicious actions that still succeeded
  after the first containment action, i.e. what the response did not prevent.
"""

from __future__ import annotations

import math
import random
import statistics
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

from .attacks import Scenario, ScenarioResult, load_scenarios
from .satellite.simulator import COMMAND_CATALOG
from .siem.engine import DetectionConfig
from .world import Defenses, build_world, run_simulation

IMPACT_EVENTS = {"uplink.transmit", "s3.GetObject", "command.submit", "downlink.frame"}


@dataclass
class TrialConfig:
    seed: int = 1
    warmup_days: float = 7.0
    measure_days: float = 7.0
    attack_spacing_h: float = 20.0
    first_attack_offset_h: float = 6.0
    #: random jitter added to each attack's start time, in hours. Without it,
    #: every trial would place the attacks at the same point of the orbital
    #: cycle and the reported variance would be an artefact of the schedule.
    attack_jitter_h: float = 8.0
    defenses: Defenses = field(default_factory=Defenses)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    archive_path: Optional[str] = None
    scenario_ids: Optional[List[str]] = None


@dataclass
class AttackOutcome:
    attack_id: str
    name: str
    t0: float
    detected: bool
    ttd_s: Optional[float]
    detecting_rules: List[str]
    all_rules: List[str]
    contained: bool
    ttc_s: Optional[float]
    containment_action: Optional[str]
    malicious_attempts: int
    malicious_successes: int
    #: impact measures with operational meaning, reported alongside the raw
    #: action count because "one executed thruster firing" and "one object read"
    #: are not comparable harms.
    critical_commands_executed: int
    bytes_exfiltrated: int
    successes_after_containment: int
    alerts: int


@dataclass
class TrialResult:
    seed: int
    duration_days: float
    measure_days: float
    outcomes: Dict[str, AttackOutcome]
    false_positives: int
    true_positive_alerts: int
    fp_per_day: float
    precision: float
    alerts_per_rule: Dict[str, Dict[str, int]]
    events: int
    defenses: Dict[str, bool]
    detection: Dict[str, float]


def run_trial(cfg: TrialConfig) -> TrialResult:
    detection = DetectionConfig(**asdict(cfg.detection))
    detection.learning = True
    world = build_world(seed=cfg.seed, defenses=cfg.defenses, detection=detection,
                        archive_path=cfg.archive_path)

    # ---- phase 1: warm-up (baseline profiling, no alerting) ----------------
    ops = run_simulation(world, cfg.warmup_days * 86400.0)
    # close any open volume buckets so the baseline has samples to work with
    for rule in world.engine.rules:
        if rule.id == "R10":
            for p in list(rule.bucket_bytes):
                rule._close_bucket(p, world.bus.log[-1])
                rule.bucket_start[p] = world.clock.now
    world.engine.config.learning = False
    world.engine.alerts.clear()
    world.engine._last_alert.clear()
    world.responder.actions.clear()
    measure_start = world.clock.now
    baseline_events = len(world.bus.log)

    # ---- phase 2: measurement with staggered attack injection --------------
    scenarios = load_scenarios()
    ids = cfg.scenario_ids or ["A1", "A2", "A3", "A4", "A5"]
    results: Dict[str, ScenarioResult] = {}
    jitter = random.Random(cfg.seed * 7919)
    for i, aid in enumerate(ids):
        scenario: Scenario = scenarios[aid]
        offset = cfg.first_attack_offset_h + i * cfg.attack_spacing_h
        offset += jitter.uniform(0.0, cfg.attack_jitter_h)
        t_start = measure_start + offset * 3600.0
        results[aid] = scenario.plan(world, t_start)

    run_simulation(world, cfg.measure_days * 86400.0, ops=ops)

    # ---- scoring -----------------------------------------------------------
    outcomes: Dict[str, AttackOutcome] = {}
    for aid, sres in results.items():
        attributed = [a for a in world.engine.alerts if aid in a.attributed_attacks]
        attributed.sort(key=lambda a: a.ts)
        first = attributed[0] if attributed else None
        actions = [
            r for r in world.responder.actions
            if r.automated and any(
                r.entity == e.actor or r.entity == e.target
                for a in attributed for e in a.evidence
            ) and r.ts >= sres.t0
        ]
        actions.sort(key=lambda r: r.ts)
        contain = actions[0] if actions else None

        mal = [e for e in world.bus.log
               if e.ground_truth == aid and e.event_type in IMPACT_EVENTS]
        successes = [e for e in mal if _is_success(e)]
        after = [e for e in successes if contain and e.ts > contain.ts]

        crit = sum(
            1 for e in world.bus.log
            if e.ground_truth == aid and e.event_type == "uplink.transmit"
            and e.attrs.get("reason") == "executed"
            and COMMAND_CATALOG.get(e.attrs.get("command"), {}).get("critical")
        )
        stolen = sum(
            e.attrs.get("bytes", 0) for e in world.bus.log
            if e.ground_truth == aid and e.event_type == "s3.GetObject"
        )
        outcomes[aid] = AttackOutcome(
            attack_id=aid, name=sres.name, t0=sres.t0,
            detected=first is not None,
            ttd_s=(first.ts - sres.t0) if first else None,
            detecting_rules=[first.rule_id] if first else [],
            all_rules=sorted({a.rule_id for a in attributed}),
            contained=contain is not None,
            ttc_s=(contain.ts - sres.t0) if contain else None,
            containment_action=contain.action if contain else None,
            malicious_attempts=len(mal),
            malicious_successes=len(successes),
            critical_commands_executed=crit,
            bytes_exfiltrated=stolen,
            successes_after_containment=len(after),
            alerts=len(attributed),
        )

    tp = [a for a in world.engine.alerts if a.is_true_positive]
    fp = [a for a in world.engine.alerts if not a.is_true_positive]
    per_rule: Dict[str, Dict[str, int]] = {}
    for a in world.engine.alerts:
        d = per_rule.setdefault(a.rule_id, {"tp": 0, "fp": 0})
        d["tp" if a.is_true_positive else "fp"] += 1

    return TrialResult(
        seed=cfg.seed,
        duration_days=cfg.warmup_days + cfg.measure_days,
        measure_days=cfg.measure_days,
        outcomes=outcomes,
        false_positives=len(fp),
        true_positive_alerts=len(tp),
        fp_per_day=len(fp) / cfg.measure_days,
        precision=(len(tp) / (len(tp) + len(fp))) if (tp or fp) else float("nan"),
        alerts_per_rule=per_rule,
        events=len(world.bus.log) - baseline_events,
        defenses=asdict(cfg.defenses),
        detection={k: v for k, v in asdict(cfg.detection).items()
                   if isinstance(v, (int, float))},
    )


def _is_success(event) -> bool:
    if event.event_type == "uplink.transmit":
        return event.attrs.get("reason") == "executed"
    if event.event_type == "s3.GetObject":
        return event.attrs.get("bytes", 0) > 0
    if event.event_type == "command.submit":
        return event.outcome == "success"
    if event.event_type == "downlink.frame":
        return event.attrs.get("injected", False)
    return False


# ------------------------------------------------------------------ statistics
def mean_ci(values: List[float], confidence: float = 0.95) -> tuple[float, float]:
    """Return (mean, half-width of the normal-approximation CI)."""
    vals = [v for v in values if v is not None]
    if not vals:
        return float("nan"), float("nan")
    if len(vals) == 1:
        return vals[0], 0.0
    m = statistics.mean(vals)
    sd = statistics.stdev(vals)
    z = 1.96 if confidence == 0.95 else 2.576
    return m, z * sd / math.sqrt(len(vals))


def aggregate(trials: List[TrialResult]) -> dict:
    """Aggregate trials into the numbers reported in the paper."""
    out: dict = {"n_trials": len(trials), "attacks": {}, "rules": {}}
    ids = sorted({aid for t in trials for aid in t.outcomes})
    for aid in ids:
        outs = [t.outcomes[aid] for t in trials if aid in t.outcomes]
        ttds = [o.ttd_s for o in outs if o.ttd_s is not None]
        ttcs = [o.ttc_s for o in outs if o.ttc_s is not None]
        m_ttd, ci_ttd = mean_ci(ttds)
        m_ttc, ci_ttc = mean_ci(ttcs)
        rule_freq: Dict[str, int] = {}
        for o in outs:
            for r in o.all_rules:
                rule_freq[r] = rule_freq.get(r, 0) + 1
        out["attacks"][aid] = {
            "name": outs[0].name,
            "detection_rate": sum(o.detected for o in outs) / len(outs),
            "containment_rate": sum(o.contained for o in outs) / len(outs),
            "ttd_mean_s": m_ttd, "ttd_ci95_s": ci_ttd,
            "ttd_median_s": statistics.median(ttds) if ttds else None,
            "ttd_min_s": min(ttds) if ttds else None,
            "ttd_max_s": max(ttds) if ttds else None,
            "ttc_mean_s": m_ttc, "ttc_ci95_s": ci_ttc,
            "first_rule_freq": _freq([o.detecting_rules[0] for o in outs if o.detecting_rules]),
            "contributing_rule_freq": rule_freq,
            "mean_malicious_successes": statistics.mean(
                [o.malicious_successes for o in outs]),
            "mean_successes_after_containment": statistics.mean(
                [o.successes_after_containment for o in outs]),
            "mean_alerts": statistics.mean([o.alerts for o in outs]),
            "mean_critical_commands_executed": statistics.mean(
                [o.critical_commands_executed for o in outs]),
            "mean_bytes_exfiltrated": statistics.mean(
                [o.bytes_exfiltrated for o in outs]),
        }
    fp_day = [t.fp_per_day for t in trials]
    m_fp, ci_fp = mean_ci(fp_day)
    prec = [t.precision for t in trials if not math.isnan(t.precision)]
    m_p, ci_p = mean_ci(prec)
    out["false_positives_per_day"] = {"mean": m_fp, "ci95": ci_fp}
    out["precision"] = {"mean": m_p, "ci95": ci_p}
    out["events_per_trial"] = statistics.mean([t.events for t in trials])
    rule_ids = sorted({r for t in trials for r in t.alerts_per_rule})
    for rid in rule_ids:
        tp = sum(t.alerts_per_rule.get(rid, {}).get("tp", 0) for t in trials)
        fp = sum(t.alerts_per_rule.get(rid, {}).get("fp", 0) for t in trials)
        out["rules"][rid] = {
            "tp": tp, "fp": fp,
            "precision": tp / (tp + fp) if (tp + fp) else float("nan"),
            "fp_per_day": fp / sum(t.measure_days for t in trials),
        }
    return out


def _freq(items: List[str]) -> Dict[str, int]:
    d: Dict[str, int] = {}
    for i in items:
        d[i] = d.get(i, 0) + 1
    return d
