# Baseline detection performance

100 independent trials, 7-day warm-up + 7-day measurement window each (5,674 events per measurement window).

Median, p95 and max are reported next to the mean because not every attack has a unimodal latency distribution: where the first-firing rule varies between trials, so does the order of magnitude of the latency, and a mean with a symmetric interval would hide that.

## Per-attack results

| ID | Attack | Detection rate | Mean TTD (s) | 95% CI | Median TTD (s) | p95 TTD (s) | Max TTD (s) | Mean TTC (s) | First-firing rule(s) | Malicious actions that succeeded |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|---:|
| A1 | Credential compromise of a mission operator account | 100% | 47.6 | ±0.5 | 48.0 | 48.0 | 48.0 | 67.6 | R01 (100) | 0.0 |
| A2 | Unauthorized telecommand against the spacecraft bus | 100% | 1,785.9 | ±1,673.6 | 4.0 | 5,924.0 | 49,544.0 | 1,824.3 | R02 (92), R05 (8) | 0.0 |
| A3 | False data injection into the telemetry stream | 100% | 13.6 | ±0.3 | 14.0 | 14.0 | 14.0 | 33.5 | R06 (100) | 27.6 |
| A4 | Replay of a captured authenticated telecommand | 100% | 4.0 | ±0.0 | 4.0 | 4.0 | 4.0 | 24.0 | R08 (93), R05 (7) | 0.0 |
| A5 | Bulk exfiltration of archived mission telemetry | 100% | 242.1 | ±2.0 | 246.0 | 246.0 | 246.0 | 262.8 | R09 (99), R10 (1) | 24.2 |

## Alert quality

- False positives: **0.45 ± 0.04 per day**
- Precision: **83.5% ± 1.3%**

| Rule | Name | Tier | TP | FP | Precision | FP/day |
|---|---|---|---:|---:|---:|---:|
| R01 | Credential brute force followed by successful logon | stream | 100 | 32 | 76% | 0.05 |
| R02 | Successful logon from unprofiled network origin | stream | 172 | 12 | 93% | 0.02 |
| R03 | Telecommand outside the principal's authorized set | stream | 92 | 0 | 100% | 0.00 |
| R04 | Critical telecommand by a principal with no such history | stream | 276 | 4 | 99% | 0.01 |
| R05 | Telecommand rejected by the spacecraft SDLS check | stream | 114 | 0 | 100% | 0.00 |
| R06 | Clustered telemetry frame integrity failures | stream | 120 | 5 | 96% | 0.01 |
| R07 | Telemetry inconsistent with subsystem physics | batch | 77 | 159 | 33% | 0.23 |
| R08 | Replayed telecommand frame | stream | 200 | 0 | 100% | 0.00 |
| R09 | Bulk enumeration of the telemetry archive | batch | 100 | 100 | 50% | 0.14 |
| R10 | Archive read volume far above the principal's baseline | batch | 100 | 0 | 100% | 0.00 |
| R11 | Security control disabled or weakened | stream | 180 | 0 | 100% | 0.00 |
