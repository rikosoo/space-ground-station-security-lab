# Research

| Path | Contents |
|---|---|
| `paper/` | LaTeX source of the paper |
| `experiments/run_experiment.py` | Every measurement: baseline, ablation, sweep, cost, dataset |
| `experiments/make_macros.py` | Turns the result JSON into the LaTeX the paper includes |
| `results/` | Generated: `*.json` (machine-readable) and `*.md` (the tables) |

## Running everything

```bash
python research/experiments/run_experiment.py all --trials 10
```

Each sub-command can also be run alone:

| Command | Answers | Output |
|---|---|---|
| `baseline` | RQ1, RQ2, RQ3 — detection rate, latency, false positives, per-rule quality | `results/baseline.*` |
| `ablation` | RQ4 — which control prevented or limited each attack | `results/ablation.*` |
| `sweep` | Sensitivity of the latency/noise trade-off to tuning | `results/sweep.*` |
| `cost` | RQ5 — monthly cost and scaling | `results/cost.*` |
| `dataset` | A labelled event log for reuse | `datasets/` |

Useful flags: `--trials` (default 10), `--warmup` and `--measure` in simulated
days (default 7 each), `--seed`.

## Experimental protocol

One trial is a warm-up window in which behavioural rules learn their baselines
and emit nothing, followed by a measurement window in which nominal operations
continue and the five attacks are injected at staggered, jittered start times.
Alerts are scored against the ground-truth labels carried by the events that
actually caused them, so a true positive is defined causally rather than by
temporal coincidence. Full definitions are in `paper/sections/06-methodology.tex`
and the implementation is `src/spacelab/experiment.py`.
