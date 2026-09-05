# Sensitivity of the detection trade-off

Each block varies one tuning parameter with everything else held at its default. The pairing of mean time to detect against false positives per day is the operating curve a SOC actually has to choose a point on.

## `integrity_threshold`

| Value | Mean TTD (s) | Detection rate | FP/day | Precision |
|---:|---:|---:|---:|---:|
| 1 | 60.5 | 100% | 1.13 | 66% |
| 2 | 61.5 | 100% | 0.56 | 79% |
| 3 | 62.5 | 100% | 0.50 | 81% |
| 5 | 64.5 | 100% | 0.47 | 82% |
| 8 | 4,282.9 | 100% | 0.47 | 81% |

## `batch_latency_s`

| Value | Mean TTD (s) | Detection rate | FP/day | Precision |
|---:|---:|---:|---:|---:|
| 30.0 | 38.5 | 100% | 0.50 | 81% |
| 150.0 | 62.5 | 100% | 0.50 | 81% |
| 300.0 | 92.5 | 100% | 0.50 | 81% |
| 900.0 | 212.5 | 100% | 0.50 | 81% |

## `exfil_key_threshold`

| Value | Mean TTD (s) | Detection rate | FP/day | Precision |
|---:|---:|---:|---:|---:|
| 10 | 50.6 | 100% | 0.50 | 81% |
| 25 | 62.5 | 100% | 0.50 | 81% |
| 50 | 82.4 | 100% | 0.50 | 81% |
| 100 | 117.2 | 100% | 0.50 | 81% |
| 200 | 206.7 | 100% | 0.50 | 80% |

## `dedup_cooldown_s`

| Value | Mean TTD (s) | Detection rate | FP/day | Precision |
|---:|---:|---:|---:|---:|
| 60.0 | 62.5 | 100% | 0.51 | 82% |
| 300.0 | 62.5 | 100% | 0.50 | 81% |
| 900.0 | 62.5 | 100% | 0.49 | 81% |
| 3600.0 | 62.5 | 100% | 0.49 | 81% |

