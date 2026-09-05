# Detection content

Eleven rules cover the five attack scenarios. Each rule exists in two forms that
are kept in step deliberately:

* **executable** - `src/spacelab/siem/rules.py`, the implementation the
  experiments measure and the deployed Lambda imports;
* **portable** - `detection-rules/sigma/*.yml`, the same logic expressed as
  Sigma so it can be converted for another backend (OpenSearch, Splunk, Sentinel)
  without reading Python.

`tests/test_rules.py` asserts that the two stay aligned: every rule id in the
Python pack must have a Sigma file and vice versa.

## Catalogue

| ID | Name | Kind | Tier | Sources | SPARTA / ATT&CK | Detects |
|---|---|---|---|---|---|---|
| R01 | Credential brute force followed by successful logon | thresholded | stream | `api.auth` | REC-0005 / T1110.003 | A1 |
| R02 | Successful logon from unprofiled network origin | behavioural | stream | `api.auth` | IA-0004 / T1078 | A1, A2, A3 |
| R03 | Telecommand outside the principal's authorized set | policy | stream | `api.command` | EX-0012 / T1078.004 | A2 |
| R04 | Critical telecommand by a principal with no such history | behavioural | stream | `api.command` | EX-0009 | A2 |
| R05 | Telecommand rejected by the spacecraft SDLS check | policy | stream | `gs.uplink` | IA-0008, EX-0016 | A2, A4 |
| R06 | Clustered telemetry frame integrity failures | thresholded | stream | `gs.downlink` | EXF-0006, IMP-0002 | A3 |
| R07 | Telemetry inconsistent with subsystem physics | behavioural | batch | `sat.telemetry` | IMP-0002 | A3 |
| R08 | Replayed telecommand frame | policy | stream | `gs.uplink`, `gs.downlink` | EX-0013 / T1499 | A4 |
| R09 | Bulk enumeration of the telemetry archive | thresholded | batch | `cloud.data` | EXF-0008 / T1530 | A5 |
| R10 | Archive read volume far above the principal's baseline | statistical | batch | `cloud.data` | EXF-0007 | A5 |
| R11 | Security control disabled or weakened | policy | stream | `cloud.audit`, `api.command` | DE-0002 / T1562 | A3, A5 |

**Tier** determines detection latency. `stream` rules run in the Lambda attached
to the Kinesis stream and see an event within seconds; `batch` rules are
scheduled queries over the log analytics tier and cannot beat their own
aggregation window. Moving a rule between tiers is the single largest lever on
mean time to detect, and `research/results/sweep.md` quantifies it.

## Tuning notes

Two rules needed tuning that is worth recording, because both lessons generalise:

1. **R06 (frame integrity)** fires on a *cluster* rather than on a single failed
   frame. A radio link corrupts frames on its own, particularly at low elevation
   at the start and end of a pass. A single-frame rule detects tampering roughly
   a minute sooner and produces enough noise to be switched off within a week -
   the exact failure mode this architecture is meant to avoid.
2. **R07 (physics)** must ignore samples whose frame already failed its
   integrity check. A corrupted frame contains implausible values by definition,
   so before this exclusion the physics rule alarmed on link noise that R06 had
   already rejected - two rules firing on one event, one of them uselessly. The
   division of labour is now explicit: R06 owns provenance, R07 owns content.
3. **R07 (physics)** must also exclude channels resting against a physical rail. A
   fully charged battery in sunlight is legitimately constant, and treating that
   as a frozen channel was the largest single source of false positives before
   the exclusion was added.
