# Baseline detection performance

100 independent trials, 7-day warm-up + 7-day measurement window each (5,823 events per measurement window).

Median, p95 and max are reported next to the mean because not every attack has a unimodal latency distribution: where the first-firing rule varies between trials, so does the order of magnitude of the latency, and a mean with a symmetric interval would hide that.

## Per-attack results

| ID | Attack | Detection rate | Mean TTD (s) | 95% CI | Median TTD (s) | p95 TTD (s) | Max TTD (s) | Mean TTC (s) | First-firing rule(s) | Malicious actions that succeeded |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|---:|
| A1 | Credential compromise of a mission operator account | 100% | 47.8 | ±0.4 | 48.0 | 48.0 | 48.0 | 67.8 | R01 (100) | 0.0 |
| A2 | Unauthorized telecommand against the spacecraft bus | 100% | 558.5 | ±976.5 | 4.0 | 4.0 | 49,534.0 | 598.1 | R02 (98), R05 (2) | 0.0 |
| A3 | False data injection into the telemetry stream | 100% | 13.6 | ±0.3 | 14.0 | 14.0 | 14.0 | 33.5 | R06 (100) | 27.9 |
| A4 | Replay of a captured authenticated telecommand | 100% | 4.0 | ±0.0 | 4.0 | 4.0 | 4.0 | 24.0 | R08 (100) | 0.0 |
| A5 | Bulk exfiltration of archived mission telemetry | 100% | 242.2 | ±1.9 | 246.0 | 246.0 | 246.0 | 263.0 | R09 (99), R10 (1) | 24.2 |

## Alert quality

- False positives: **0.80 ± 0.05 per day**
- Precision: **74.2% ± 1.2%**

| Rule | Name | Tier | TP | FP | Precision | FP/day |
|---|---|---|---:|---:|---:|---:|
| R01 | Credential brute force followed by successful logon | stream | 100 | 31 | 76% | 0.04 |
| R02 | Successful logon from unprofiled network origin | stream | 193 | 27 | 88% | 0.04 |
| R03 | Telecommand outside the principal's authorized set | stream | 98 | 0 | 100% | 0.00 |
| R04 | Critical telecommand by a principal with no such history | stream | 294 | 17 | 95% | 0.02 |
| R05 | Telecommand rejected by the spacecraft SDLS check | stream | 100 | 0 | 100% | 0.00 |
| R06 | Clustered telemetry frame integrity failures | stream | 105 | 4 | 96% | 0.01 |
| R07 | Telemetry inconsistent with subsystem physics | batch | 92 | 380 | 19% | 0.54 |
| R08 | Replayed telecommand frame | stream | 200 | 0 | 100% | 0.00 |
| R09 | Bulk enumeration of the telemetry archive | batch | 100 | 100 | 50% | 0.14 |
| R10 | Archive read volume far above the principal's baseline | batch | 100 | 0 | 100% | 0.00 |
| R11 | Security control disabled or weakened | stream | 195 | 0 | 100% | 0.00 |
