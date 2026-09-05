# Cost of the architecture

Derived from the measured workload of 809 security events per day for a single spacecraft and one ground station. US East (N. Virginia) on-demand list prices collected 2026-01; no committed-use discounts, no free tier.

| Service | Cost driver | Quantity | Unit | USD/month |
|---|---|---:|---|---:|
| OpenSearch Serverless | indexing + search OCUs | 1,440.0 | OCU-hour | 345.60 |
| Kinesis Data Streams | stream-hours (on-demand) | 720.0 | stream-hour | 28.80 |
| S3 | telemetry archive storage | 1,012.5 | GB-month | 23.29 |
| CloudWatch | alarms + custom metrics | 65.0 | resource | 14.50 |
| Security Hub | findings ingested | 90.0 | finding | 5.00 |
| KMS | key + cryptographic requests | 2.0 | key | 2.07 |
| EventBridge | rule matches | 24,272.1 | event | 0.02 |
| GuardDuty | CloudTrail + S3 data analysed | 0.0 | GB | 0.02 |
| Lambda | detection + response invocations | 24,272.1 | invocation | 0.01 |
| S3 | PUT/GET requests | 10,800.0 | request | 0.01 |
| CloudWatch Logs | log ingestion | 0.0 | GB | 0.01 |
| CloudTrail | S3 data events | 10,800.0 | event | 0.01 |
| CloudWatch Logs | log retention | 0.1 | GB-month | 0.00 |
| Kinesis Data Streams | ingested telemetry + security events | 0.0 | GB | 0.00 |
| SNS | analyst notifications | 90.0 | notification | 0.00 |
| **Total** | | | | **419.36** |

## Scaling

| Spacecraft | Events/day | USD/month | USD/spacecraft/month |
|---:|---:|---:|---:|
| 1 | 809 | 419.36 | 419.36 |
| 10 | 8,091 | 1,660.77 | 166.08 |
| 100 | 80,907 | 7,989.01 | 79.89 |

The per-spacecraft cost falls by roughly an order of magnitude between one and one hundred spacecraft because the analytics tier is a fixed platform cost: at lab scale the architecture is dominated by the minimum billable capacity of the search tier, not by event volume.
