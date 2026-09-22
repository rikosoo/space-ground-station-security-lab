#!/usr/bin/env python3
"""Command-line entry point for every measurement reported in the paper.

Sub-commands
------------
``baseline``   detection rate, time to detect, time to contain, false positives
``ablation``   defence-in-depth ablation: which mechanism actually did the work
``sweep``      sensitivity of the detection/latency trade-off to rule tuning
``cost``       monthly cost of the architecture at three fleet sizes
``dataset``    export a labelled event log for reuse by other researchers
``all``        run everything and refresh research/results/

Results are written as JSON (machine-readable, for re-analysis) and Markdown
(the tables that go into the paper).
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import pathlib
import statistics
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from spacelab.cost import Workload, estimate, scaling_table  # noqa: E402
from spacelab.experiment import TrialConfig, aggregate, run_trial  # noqa: E402
from spacelab.siem.engine import DetectionConfig  # noqa: E402
from spacelab.siem.rules import ALL_RULES  # noqa: E402
from spacelab.world import Defenses  # noqa: E402

RESULTS = ROOT / "research" / "results"
DATASETS = ROOT / "datasets"


def _fmt(v, nd=1):
    return "-" if v is None else f"{v:,.{nd}f}"


def _write(name: str, payload: dict, markdown: str) -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / f"{name}.json").write_text(json.dumps(payload, indent=2, default=str))
    (RESULTS / f"{name}.md").write_text(markdown)
    print(f"  wrote research/results/{name}.json and .md")


# --------------------------------------------------------------------- baseline
def cmd_baseline(args) -> dict:
    n = args.baseline_trials
    trials = []
    t0 = time.time()
    for i in range(n):
        cfg = TrialConfig(seed=args.seed + i, warmup_days=args.warmup,
                          measure_days=args.measure)
        trials.append(run_trial(cfg))
        if (i + 1) % 10 == 0 or i + 1 == n:
            print(f"  trial {i + 1}/{n} (seed {cfg.seed}) done", flush=True)
    agg = aggregate(trials)
    agg["wall_time_s"] = round(time.time() - t0, 1)
    agg["config"] = {"trials": n, "warmup_days": args.warmup,
                     "measure_days": args.measure, "seed0": args.seed}

    lines = ["# Baseline detection performance", "",
             f"{n} independent trials, {args.warmup:.0f}-day warm-up + "
             f"{args.measure:.0f}-day measurement window each "
             f"({agg['events_per_trial']:,.0f} events per measurement window).", "",
             "Median, p95 and max are reported next to the mean because not every "
             "attack has a unimodal latency distribution: where the first-firing "
             "rule varies between trials, so does the order of magnitude of the "
             "latency, and a mean with a symmetric interval would hide that.", "",
             "## Per-attack results", "",
             "| ID | Attack | Detection rate | Mean TTD (s) | 95% CI | Median TTD (s) "
             "| p95 TTD (s) | Max TTD (s) | Mean TTC (s) | First-firing rule(s) "
             "| Malicious actions that succeeded |",
             "|---|---|---:|---:|---:|---:|---:|---:|---:|---|---:|"]
    for aid, a in agg["attacks"].items():
        rules = ", ".join(f"{k} ({v})" for k, v in sorted(
            a["first_rule_freq"].items(), key=lambda kv: -kv[1]))
        lines.append(
            f"| {aid} | {a['name']} | {a['detection_rate']:.0%} | "
            f"{_fmt(a['ttd_mean_s'])} | ±{_fmt(a['ttd_ci95_s'])} | "
            f"{_fmt(a['ttd_median_s'])} | {_fmt(a['ttd_p95_s'])} | "
            f"{_fmt(a['ttd_max_s'])} | {_fmt(a['ttc_mean_s'])} | {rules} | "
            f"{a['mean_malicious_successes']:.1f} |")
    lines += ["", "## Alert quality", "",
              f"- False positives: **{agg['false_positives_per_day']['mean']:.2f} "
              f"± {agg['false_positives_per_day']['ci95']:.2f} per day**",
              f"- Precision: **{agg['precision']['mean']:.1%} "
              f"± {agg['precision']['ci95']:.1%}**", "",
              "| Rule | Name | Tier | TP | FP | Precision | FP/day |",
              "|---|---|---|---:|---:|---:|---:|"]
    names = {r.id: (r.name, r.tier) for r in ALL_RULES}
    for rid in sorted(set(names) | set(agg["rules"])):
        st = agg["rules"].get(rid, {"tp": 0, "fp": 0, "precision": float("nan"),
                                    "fp_per_day": 0.0})
        name, tier = names.get(rid, ("-", "-"))
        prec = "-" if st["tp"] + st["fp"] == 0 else f"{st['precision']:.0%}"
        lines.append(f"| {rid} | {name} | {tier} | {st['tp']} | {st['fp']} | {prec} | "
                     f"{st['fp_per_day']:.2f} |")
    _write("baseline", agg, "\n".join(lines) + "\n")
    return agg


# --------------------------------------------------------------------- ablation
ABLATIONS = [
    ("full", {}),
    ("no_mfa", {"mfa": False}),
    ("no_rbac", {"rbac": False}),
    ("no_sdls_auth", {"sdls_authentication": False}),
    ("no_anti_replay", {"anti_replay_window": False}),
    ("no_rate_limit", {"rate_limit": False}),
    ("no_pass_window", {"pass_window_check": False}),
    ("no_auto_response", {"auto_response": False}),
    ("none", {"mfa": False, "rbac": False, "sdls_authentication": False,
              "anti_replay_window": False, "rate_limit": False,
              "pass_window_check": False, "auto_response": False}),
]


def cmd_ablation(args) -> dict:
    out = {"configurations": {}}
    for label, off in ABLATIONS:
        defenses = Defenses(**{**dataclasses.asdict(Defenses()), **off})
        trials = [run_trial(TrialConfig(seed=args.seed + i, warmup_days=args.warmup,
                                        measure_days=args.measure, defenses=defenses))
                  for i in range(args.trials)]
        agg = aggregate(trials)
        succ = {aid: agg["attacks"][aid]["mean_malicious_successes"]
                for aid in agg["attacks"]}
        crit = sum(agg["attacks"][a]["mean_critical_commands_executed"]
                   for a in agg["attacks"])
        stolen = sum(agg["attacks"][a]["mean_bytes_exfiltrated"]
                     for a in agg["attacks"])
        out["configurations"][label] = {
            "disabled": list(off),
            "detection_rate": statistics.mean(
                [agg["attacks"][a]["detection_rate"] for a in agg["attacks"]]),
            "mean_ttd_s": statistics.mean(
                [agg["attacks"][a]["ttd_mean_s"] for a in agg["attacks"]
                 if agg["attacks"][a]["ttd_mean_s"] == agg["attacks"][a]["ttd_mean_s"]]),
            "total_malicious_successes": sum(succ.values()),
            "critical_commands_executed": crit,
            "mb_exfiltrated": stolen / 1e6,
            "successes_by_attack": succ,
            "fp_per_day": agg["false_positives_per_day"]["mean"],
            "attacks": agg["attacks"],
        }
        print(f"  {label:16s} successes={sum(succ.values()):6.1f} "
              f"det={out['configurations'][label]['detection_rate']:.0%}", flush=True)

    lines = ["# Defence ablation", "",
             "Each row disables exactly one preventive or responsive control and "
             "repeats the full campaign. *Successful malicious actions* counts "
             "adversary actions that took effect (command executed, object read, "
             "forged frame accepted); it is the impact measure. Detection rate is "
             "averaged over the five attacks.", "",
             "| Configuration | Control removed | Detection rate | Mean TTD (s) "
             "| Successful malicious actions | Critical commands executed "
             "| MB exfiltrated | FP/day |",
             "|---|---|---:|---:|---:|---:|---:|---:|"]
    for label, cfg in out["configurations"].items():
        lines.append(
            f"| {label} | {', '.join(cfg['disabled']) or '-'} | "
            f"{cfg['detection_rate']:.0%} | {_fmt(cfg['mean_ttd_s'])} | "
            f"{cfg['total_malicious_successes']:.1f} | "
            f"{cfg['critical_commands_executed']:.1f} | "
            f"{cfg['mb_exfiltrated']:,.0f} | {cfg['fp_per_day']:.2f} |")
    lines += ["", "## Per-attack impact by configuration", "",
              "| Configuration | " + " | ".join(sorted(
                  out["configurations"]["full"]["successes_by_attack"])) + " |",
              "|---|" + "---:|" * len(out["configurations"]["full"]["successes_by_attack"])]
    for label, cfg in out["configurations"].items():
        row = " | ".join(f"{cfg['successes_by_attack'][a]:.1f}"
                         for a in sorted(cfg["successes_by_attack"]))
        lines.append(f"| {label} | {row} |")
    _write("ablation", out, "\n".join(lines) + "\n")
    return out


# ------------------------------------------------------------------------ sweep
SWEEPS = {
    "integrity_threshold": [1, 2, 3, 5, 8],
    "batch_latency_s": [30.0, 150.0, 300.0, 900.0],
    "exfil_key_threshold": [10, 25, 50, 100, 200],
    "dedup_cooldown_s": [60.0, 300.0, 900.0, 3600.0],
}


def cmd_sweep(args) -> dict:
    out: dict = {"sweeps": {}}
    for param, values in SWEEPS.items():
        rows = []
        for v in values:
            det = DetectionConfig(**{param: v})
            trials = [run_trial(TrialConfig(seed=args.seed + i, warmup_days=args.warmup,
                                            measure_days=args.measure, detection=det))
                      for i in range(args.trials)]
            agg = aggregate(trials)
            ttds = [agg["attacks"][a]["ttd_mean_s"] for a in agg["attacks"]
                    if agg["attacks"][a]["ttd_mean_s"] is not None]
            rows.append({
                "value": v,
                "mean_ttd_s": statistics.mean(ttds) if ttds else None,
                "detection_rate": statistics.mean(
                    [agg["attacks"][a]["detection_rate"] for a in agg["attacks"]]),
                "fp_per_day": agg["false_positives_per_day"]["mean"],
                "precision": agg["precision"]["mean"],
            })
            print(f"  {param}={v}: ttd={rows[-1]['mean_ttd_s']:.1f}s "
                  f"fp/day={rows[-1]['fp_per_day']:.2f}", flush=True)
        out["sweeps"][param] = rows

    lines = ["# Sensitivity of the detection trade-off", "",
             "Each block varies one tuning parameter with everything else held at "
             "its default. The pairing of mean time to detect against false "
             "positives per day is the operating curve a SOC actually has to "
             "choose a point on.", ""]
    for param, rows in out["sweeps"].items():
        lines += [f"## `{param}`", "",
                  "| Value | Mean TTD (s) | Detection rate | FP/day | Precision |",
                  "|---:|---:|---:|---:|---:|"]
        for r in rows:
            lines.append(f"| {r['value']} | {_fmt(r['mean_ttd_s'])} | "
                         f"{r['detection_rate']:.0%} | {r['fp_per_day']:.2f} | "
                         f"{r['precision']:.0%} |")
        lines.append("")
    _write("sweep", out, "\n".join(lines) + "\n")
    return out


# ------------------------------------------------------------------------- cost
def cmd_cost(args) -> dict:
    baseline_path = RESULTS / "baseline.json"
    events_per_day = 800.0
    if baseline_path.exists():
        data = json.loads(baseline_path.read_text())
        events_per_day = data["events_per_trial"] / data["config"]["measure_days"]
    w = Workload(security_events_per_day=events_per_day)
    rep = estimate(w)
    payload = {
        "workload": dataclasses.asdict(w),
        "total_monthly_usd": rep.total,
        "lines": [dataclasses.asdict(ln) for ln in rep.lines],
        "scaling": scaling_table(w),
    }
    md = ["# Cost of the architecture", "",
          f"Derived from the measured workload of {events_per_day:,.0f} security "
          f"events per day for a single spacecraft and one ground station. "
          "US East (N. Virginia) on-demand list prices collected 2026-01; no "
          "committed-use discounts, no free tier.", "",
          rep.as_table(), "", "## Scaling", "", scaling_table(w), "",
          "The per-spacecraft cost falls by roughly an order of magnitude between "
          "one and one hundred spacecraft because the analytics tier is a fixed "
          "platform cost: at lab scale the architecture is dominated by the "
          "minimum billable capacity of the search tier, not by event volume.", ""]
    _write("cost", payload, "\n".join(md))
    return payload


# ---------------------------------------------------------------------- dataset
def cmd_dataset(args) -> dict:
    DATASETS.mkdir(parents=True, exist_ok=True)
    path = DATASETS / "labelled-events.jsonl"
    cfg = TrialConfig(seed=args.seed, warmup_days=args.warmup,
                      measure_days=args.measure, archive_path=str(path))
    result = run_trial(cfg)
    n = sum(1 for _ in open(path))
    meta = {
        "file": path.name, "events": n, "seed": args.seed,
        "warmup_days": args.warmup, "measure_days": args.measure,
        "labels": sorted({o.attack_id for o in result.outcomes.values()}) + ["benign"],
        "schema": "see src/spacelab/events.py",
        "outcomes": {k: dataclasses.asdict(v) for k, v in result.outcomes.items()},
    }
    (DATASETS / "labelled-events.meta.json").write_text(json.dumps(meta, indent=2))
    print(f"  wrote datasets/{path.name} ({n:,} events)")
    return meta


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["baseline", "ablation", "sweep", "cost",
                                        "dataset", "all"])
    ap.add_argument("--trials", type=int, default=10,
                    help="trials per configuration for ablation and sweep, where "
                         "only the mean is reported")
    ap.add_argument("--baseline-trials", type=int, default=100,
                    help="trials for the baseline campaign. Higher than --trials "
                         "because the baseline is where per-attack latency "
                         "variance is characterised, and A2's tail is rare "
                         "enough that ten trials can miss it entirely")
    ap.add_argument("--seed", type=int, default=1000)
    ap.add_argument("--warmup", type=float, default=7.0)
    ap.add_argument("--measure", type=float, default=7.0)
    args = ap.parse_args()

    order = ([args.command] if args.command != "all"
             else ["baseline", "ablation", "sweep", "cost", "dataset"])
    for name in order:
        print(f"[{name}]")
        globals()[f"cmd_{name}"](args)


if __name__ == "__main__":
    main()
