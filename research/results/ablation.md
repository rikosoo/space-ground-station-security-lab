# Defence ablation

Each row disables exactly one preventive or responsive control and repeats the full campaign. *Successful malicious actions* counts adversary actions that took effect (command executed, object read, forged frame accepted); it is the impact measure. Detection rate is averaged over the five attacks.

| Configuration | Control removed | Detection rate | Mean TTD (s) | Successful malicious actions | Critical commands executed | MB exfiltrated | FP/day |
|---|---|---:|---:|---:|---:|---:|---:|
| full | - | 100% | 62.6 | 52.0 | 0.9 | 1,218 | 0.86 |
| no_mfa | mfa | 100% | 62.6 | 52.0 | 0.9 | 1,218 | 0.86 |
| no_rbac | rbac | 100% | 62.6 | 54.0 | 1.9 | 1,218 | 0.89 |
| no_sdls_auth | sdls_authentication | 100% | 62.6 | 54.0 | 2.9 | 1,218 | 0.86 |
| no_anti_replay | anti_replay_window | 100% | 62.6 | 55.0 | 0.9 | 1,218 | 0.84 |
| no_rate_limit | rate_limit | 100% | 62.6 | 52.0 | 0.9 | 1,218 | 0.86 |
| no_pass_window | pass_window_check | 100% | 62.6 | 52.0 | 0.9 | 1,218 | 0.86 |
| no_auto_response | auto_response | 100% | 62.5 | 288.0 | 1.0 | 13,086 | 1.00 |
| no_block_expiry | block_ttl_s | 100% | 62.5 | 51.7 | 0.8 | 1,213 | 0.50 |
| none | mfa, rbac, sdls_authentication, anti_replay_window, rate_limit, pass_window_check, auto_response | 100% | 62.5 | 306.0 | 6.6 | 13,086 | 1.14 |

## Per-attack impact by configuration

| Configuration | A1 | A2 | A3 | A4 | A5 |
|---|---:|---:|---:|---:|---:|
| full | 0.0 | 0.0 | 27.8 | 0.0 | 24.2 |
| no_mfa | 0.0 | 0.0 | 27.8 | 0.0 | 24.2 |
| no_rbac | 0.0 | 2.0 | 27.8 | 0.0 | 24.2 |
| no_sdls_auth | 0.0 | 2.0 | 27.8 | 0.0 | 24.2 |
| no_anti_replay | 0.0 | 0.0 | 27.8 | 3.0 | 24.2 |
| no_rate_limit | 0.0 | 0.0 | 27.8 | 0.0 | 24.2 |
| no_pass_window | 0.0 | 0.0 | 27.8 | 0.0 | 24.2 |
| no_auto_response | 0.0 | 0.0 | 28.0 | 0.0 | 260.0 |
| no_block_expiry | 0.0 | 0.0 | 27.6 | 0.0 | 24.1 |
| none | 6.0 | 9.0 | 28.0 | 3.0 | 260.0 |
