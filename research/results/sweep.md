# Sensitivity of the detection trade-off

Each block varies one tuning parameter with everything else held at its default. The pairing of mean time to detect against false positives per day is the operating curve a SOC actually has to choose a point on.

## `integrity_threshold`

| Value | Mean TTD (s) | Detection rate | FP/day | Precision |
|---:|---:|---:|---:|---:|
| 1 | 60.5 | 100% | 1.13 | 67% |
| 2 | 61.5 | 100% | 0.56 | 80% |
| 3 | 62.5 | 100% | 0.50 | 82% |
| 5 | 64.5 | 100% | 0.47 | 83% |
| 8 | 4,282.9 | 100% | 0.47 | 82% |

## `batch_latency_s`

| Value | Mean TTD (s) | Detection rate | FP/day | Precision |
|---:|---:|---:|---:|---:|
| 30.0 | 38.5 | 100% | 0.50 | 82% |
| 150.0 | 62.5 | 100% | 0.50 | 82% |
| 300.0 | 92.5 | 100% | 0.50 | 82% |
| 900.0 | 212.5 | 100% | 0.50 | 82% |

## `exfil_key_threshold`

| Value | Mean TTD (s) | Detection rate | FP/day | Precision |
|---:|---:|---:|---:|---:|
| 10 | 50.6 | 100% | 0.50 | 82% |
| 25 | 62.5 | 100% | 0.50 | 82% |
| 50 | 80.9 | 100% | 0.50 | 82% |
| 100 | 117.0 | 100% | 0.50 | 82% |
| 200 | 212.1 | 100% | 0.50 | 81% |

## `dedup_cooldown_s`

| Value | Mean TTD (s) | Detection rate | FP/day | Precision |
|---:|---:|---:|---:|---:|
| 60.0 | 62.5 | 100% | 0.51 | 83% |
| 300.0 | 62.5 | 100% | 0.50 | 82% |
| 900.0 | 62.5 | 100% | 0.49 | 82% |
| 3600.0 | 62.5 | 100% | 0.49 | 82% |

