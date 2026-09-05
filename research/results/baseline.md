# Baseline detection performance

10 independent trials, 7-day warm-up + 7-day measurement window each (5,664 events per measurement window).

## Per-attack results

| ID | Attack | Detection rate | Mean TTD (s) | 95% CI | Median TTD (s) | Mean TTC (s) | First-firing rule(s) | Malicious actions that succeeded |
|---|---|---:|---:|---:|---:|---:|---|---:|
| A1 | Credential compromise of a mission operator account | 100% | 48.0 | ±0.0 | 48.0 | 68.0 | R01 (10) | 0.0 |
| A2 | Unauthorized telecommand against the spacecraft bus | 100% | 4.0 | ±0.0 | 4.0 | 44.0 | R02 (10) | 0.0 |
| A3 | False data injection into the telemetry stream | 100% | 14.0 | ±0.0 | 14.0 | 34.0 | R06 (10) | 27.6 |
| A4 | Replay of a captured authenticated telecommand | 100% | 4.0 | ±0.0 | 4.0 | 24.0 | R08 (9), R05 (1) | 0.0 |
| A5 | Bulk exfiltration of archived mission telemetry | 100% | 242.5 | ±4.5 | 246.0 | 262.5 | R09 (10) | 24.1 |

## Alert quality

- False positives: **0.50 ± 0.12 per day**
- Precision: **81.2% ± 3.7%**

| Rule | Name | Tier | TP | FP | Precision | FP/day |
|---|---|---|---:|---:|---:|---:|
| R01 | Credential brute force followed by successful logon | stream | 10 | 1 | 91% | 0.01 |
| R02 | Successful logon from unprofiled network origin | stream | 18 | 2 | 90% | 0.03 |
| R03 | Telecommand outside the principal's authorized set | stream | 10 | 0 | 100% | 0.00 |
| R04 | Critical telecommand by a principal with no such history | stream | 30 | 0 | 100% | 0.00 |
| R05 | Telecommand rejected by the spacecraft SDLS check | stream | 12 | 0 | 100% | 0.00 |
| R06 | Clustered telemetry frame integrity failures | stream | 12 | 2 | 86% | 0.03 |
| R07 | Telemetry inconsistent with subsystem physics | batch | 8 | 20 | 29% | 0.29 |
| R08 | Replayed telecommand frame | stream | 20 | 0 | 100% | 0.00 |
| R09 | Bulk enumeration of the telemetry archive | batch | 10 | 10 | 50% | 0.14 |
| R10 | Archive read volume far above the principal's baseline | batch | 0 | 0 | - | 0.00 |
| R11 | Security control disabled or weakened | stream | 18 | 0 | 100% | 0.00 |
