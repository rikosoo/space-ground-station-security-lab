"""Streaming detection engine.

Design notes that matter for the measurements:

* **Pipeline latency is explicit.** A rule declares a tier - ``stream`` (a
  Lambda consumer on the telemetry stream) or ``batch`` (a scheduled query in
  the log analytics tier). The alert timestamp is the triggering event's
  timestamp plus that tier's latency, so the reported mean time to detect
  includes the architecture's own delay rather than pretending detection is
  instantaneous.
* **Alerts carry their evidence.** Every alert references the events that
  produced it. Scoring compares an alert against the ground-truth labels of its
  evidence, so a true positive is one that was actually caused by attack
  activity rather than one that merely coincided with it in time.
* **Deduplication is part of the system under test.** Without a per-entity
  cooldown, a single incident produces an alert storm and the false-positive
  rate becomes meaningless. The cooldown is therefore a tunable parameter, not
  a hidden implementation detail.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from ..events import Event


@dataclass
class DetectionConfig:
    """Tunable parameters of the detection tier (swept in the experiments)."""

    stream_latency_s: float = 4.0        # Kinesis -> Lambda -> alert
    batch_latency_s: float = 150.0       # scheduled OpenSearch query, 5 min cadence
    dedup_cooldown_s: float = 300.0
    integrity_threshold: int = 3         # frames within the window (R05)
    integrity_window_s: float = 120.0
    auth_fail_threshold: int = 5
    auth_fail_window_s: float = 300.0
    exfil_key_threshold: int = 25
    exfil_window_s: float = 600.0
    exfil_zscore: float = 4.0
    learning: bool = False               # baseline-profiling mode


@dataclass
class Alert:
    ts: float                 # when the SOC could first act on it
    trigger_ts: float         # timestamp of the triggering event
    rule_id: str
    rule_name: str
    severity: str
    entity: str
    technique: str
    tier: str
    evidence: List[Event] = field(default_factory=list)
    detail: Dict = field(default_factory=dict)

    @property
    def truths(self) -> Set[str]:
        return {e.ground_truth for e in self.evidence}

    @property
    def is_true_positive(self) -> bool:
        return any(t != "benign" for t in self.truths)

    @property
    def attributed_attacks(self) -> Set[str]:
        return {t for t in self.truths if t != "benign"}


class Baseline:
    """Per-principal behavioural profile learned during the warm-up window."""

    def __init__(self) -> None:
        self.known_ips: Dict[str, Set[str]] = {}
        self.known_asns: Dict[str, Set[str]] = {}
        self.known_agents: Dict[str, Set[str]] = {}
        self.critical_command_users: Set[str] = set()
        self.read_bytes_hourly: Dict[str, List[float]] = {}

    def observe_login(self, user: str, ip: str, asn: str, agent: str) -> None:
        self.known_ips.setdefault(user, set()).add(ip)
        self.known_asns.setdefault(user, set()).add(asn)
        self.known_agents.setdefault(user, set()).add(agent)

    def stats(self, principal: str) -> tuple[float, float]:
        vals = self.read_bytes_hourly.get(principal, [])
        if len(vals) < 3:
            return 0.0, 0.0
        mean = sum(vals) / len(vals)
        var = sum((v - mean) ** 2 for v in vals) / (len(vals) - 1)
        return mean, var**0.5


class DetectionEngine:
    """Consumes normalized events and produces deduplicated alerts."""

    def __init__(self, config: Optional[DetectionConfig] = None) -> None:
        self.config = config or DetectionConfig()
        self.baseline = Baseline()
        self.alerts: List[Alert] = []
        self._last_alert: Dict[tuple, float] = {}
        # imported here rather than at module scope: the rules import the engine
        from .rules import ALL_RULES

        self.rules: List = [r(self) for r in ALL_RULES]

    # ------------------------------------------------------------------ core
    def consume(self, event: Event) -> None:
        # Event time is the only clock the engine has, and it advances whoever
        # produced the event. A scheduled rule therefore still runs while one
        # principal is silent, as long as the ground segment as a whole is not.
        now = event.ts
        for rule in self.rules:
            for alert in rule.tick(now) or []:
                self._emit(alert)
            for alert in rule.evaluate(event) or []:
                self._emit(alert)

    def _emit(self, alert: Alert) -> None:
        key = (alert.rule_id, alert.entity)
        last = self._last_alert.get(key)
        if last is not None and alert.trigger_ts - last < self.config.dedup_cooldown_s:
            return
        self._last_alert[key] = alert.trigger_ts
        self.alerts.append(alert)

    def latency_for(self, tier: str) -> float:
        return (
            self.config.stream_latency_s if tier == "stream"
            else self.config.batch_latency_s
        )
