# Datasets

`labelled-events.jsonl` is the full event log of one complete trial — a 7-day
baseline-learning window plus a 7-day measurement window containing all five
attacks — with every event labelled `benign` or with its attack identifier.
`labelled-events.meta.json` records the seed, the window lengths, the label set
and the scored outcome of each attack.

Regenerate with:

```bash
python research/experiments/run_experiment.py dataset --seed 1000
```

## Schema

One JSON object per line; the authoritative definition is
[`src/spacelab/events.py`](../src/spacelab/events.py).

| Field | Type | Meaning |
|---|---|---|
| `ts` | float | Simulated epoch seconds |
| `source` | string | `api.auth`, `api.command`, `gs.uplink`, `gs.downlink`, `sat.telemetry`, `cloud.audit`, `cloud.data`, `ir.action` |
| `event_type` | string | Dotted verb, e.g. `auth.login`, `command.submit`, `s3.GetObject` |
| `actor` | string | Principal that caused the event |
| `target` | string | Object acted upon |
| `outcome` | string | `success` or `failure` |
| `src_ip` | string | Network origin where meaningful |
| `attrs` | object | Rule-specific detail |
| `ground_truth` | string | `benign`, or `A1`–`A5` |

## Using it for something else

The log is intended to be reusable as a labelled benchmark for ground-segment
detection research — for training or evaluating a detector that is not the rule
pack in this repository. Two cautions if you do:

1. **`ground_truth` is not an input.** It exists to score a detector, not to feed
   one. The rule pack in this repository is tested to ensure it never reads it.
2. **The workload is synthetic.** Its benign anomalies are realistic in kind but
   their rates are chosen, so absolute false-positive rates measured against this
   log are not a prediction for a real mission.
