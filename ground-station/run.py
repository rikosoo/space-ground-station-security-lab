#!/usr/bin/env python3
"""Run a nominal ground-station shift and print what the SIEM saw."""

from __future__ import annotations

import argparse
import collections
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from spacelab.world import build_world, run_simulation  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hours", type=float, default=12.0)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--archive", type=str, default="")
    args = ap.parse_args()

    world = build_world(seed=args.seed, archive_path=args.archive or None)
    run_simulation(world, args.hours * 3600.0)

    by_source = collections.Counter(e.source for e in world.bus.log)
    print(f"simulated {args.hours:g} h, {len(world.bus.log):,} events")
    for source, n in by_source.most_common():
        print(f"  {source:16s} {n:6,}")

    frames = [e for e in world.bus.log if e.event_type == "downlink.frame"]
    bad = [e for e in frames if e.attrs.get("integrity") != "ok"]
    print(f"\ndownlinked frames   : {len(frames):,}")
    print(f"integrity failures  : {len(bad)} "
          f"({len(bad) / max(len(frames), 1):.3%} - link noise)")

    print(f"\nalerts: {len(world.engine.alerts)}")
    for a in world.engine.alerts:
        print(f"  t+{a.trigger_ts - world.clock.t0:8.0f}s  {a.rule_id} [{a.severity:8s}] "
              f"{a.entity:14s} {a.rule_name}")
    if world.responder.actions:
        print("\nautomated containment:")
        for r in world.responder.actions:
            print(f"  t+{r.ts - world.clock.t0:8.0f}s  {r.alert_rule}  {r.action} "
                  f"-> {r.entity}")


if __name__ == "__main__":
    main()
