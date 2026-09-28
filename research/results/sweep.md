# Sensitivity of the detection trade-off

Each block varies one tuning parameter with everything else held at its default. The pairing of mean time to detect against false positives per day is the operating curve a SOC actually has to choose a point on.

## `integrity_threshold`

| Value | Mean TTD (s) | Detection rate | FP/day | Precision |
|---:|---:|---:|---:|---:|
| 1 | 60.6 | 100% | 1.41 | 63% |
| 2 | 61.6 | 100% | 0.90 | 72% |
| 3 | 62.6 | 100% | 0.86 | 73% |
| 5 | 64.6 | 100% | 0.84 | 73% |
| 8 | 4,281.3 | 100% | 0.84 | 72% |

## `batch_latency_s`

| Value | Mean TTD (s) | Detection rate | FP/day | Precision |
|---:|---:|---:|---:|---:|
| 30.0 | 38.6 | 100% | 0.86 | 73% |
| 150.0 | 62.6 | 100% | 0.86 | 73% |
| 300.0 | 92.6 | 100% | 0.86 | 73% |
| 900.0 | 212.6 | 100% | 0.86 | 73% |

## `exfil_key_threshold`

| Value | Mean TTD (s) | Detection rate | FP/day | Precision |
|---:|---:|---:|---:|---:|
| 10 | 50.6 | 100% | 0.86 | 73% |
| 25 | 62.6 | 100% | 0.86 | 73% |
| 50 | 81.0 | 100% | 0.86 | 73% |
| 100 | 117.0 | 100% | 0.86 | 73% |
| 200 | 212.1 | 100% | 0.86 | 72% |

## `dedup_cooldown_s`

| Value | Mean TTD (s) | Detection rate | FP/day | Precision |
|---:|---:|---:|---:|---:|
| 60.0 | 62.6 | 100% | 0.86 | 74% |
| 300.0 | 62.6 | 100% | 0.86 | 73% |
| 900.0 | 62.6 | 100% | 0.84 | 72% |
| 3600.0 | 62.6 | 100% | 0.84 | 72% |

