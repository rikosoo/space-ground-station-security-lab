# Space Ground Station Security Lab

> **Can cloud-native security telemetry effectively detect cyberattacks against
> simulated satellite ground segments?**

A reproducible testbed that answers that question with measurements rather than
with a diagram. It simulates a full satellite ground segment — spacecraft,
ground station, mission-control API, cloud analytics, incident response — runs
five controlled attacks against it, and reports for each one how long detection
took, which log made it visible, how many false positives the same detections
produced in a week of benign operations, which defensive mechanism actually
stopped the attack, and what the architecture costs to run.

```
Satellite simulator  ->  Ground station  ->  Mission-control API
                                                     |
                                                     v
                          AWS: Kinesis · S3 · CloudTrail · EventBridge
                               Lambda · CloudWatch · Security Hub
                                                     |
                                                     v
                          Detection  ->  Alert  ->  Automated containment
                                                     |
                                                     v
                                        Incident-response playbooks
```

Everything runs on a laptop with no AWS account and no dependencies beyond the
Python standard library. Fourteen simulated days take about two seconds, which
is what makes ten-trial confidence intervals affordable.

## Headline results

Ten trials, each a 7-day baseline-learning window followed by a 7-day
measurement window containing all five attacks (about 5,700 events per window).
Regenerate with `python research/experiments/run_experiment.py all`.

| Attack | Detected | Mean time to detect | First rule to fire | What stopped it |
|---|---|---|---|---|
| A1 Credential compromise | 10/10 | 48 s | R01 brute force | Detecting the spray and revoking the account, before MFA was even tested |
| A2 Unauthorized command | 10/10 | 4 s | R02 unprofiled origin | RBAC allowlist; SDLS tag for the RF variant |
| A3 Telemetry tampering | 10/10 | 14 s | R06 frame integrity | Nothing prevented it; physics analytics caught the stealth phase |
| A4 Replay | 10/10 | 4 s | R08 replay | Spacecraft anti-replay window |
| A5 Exfiltration | 10/10 | 243 s | R09 bulk enumeration | Automated archive deny, after ~24 objects |

False positives: **0.50 ± 0.12 per day**, precision **81.2%**. Modelled cost:
**~USD 420/month** for one spacecraft, falling to **~USD 80 per spacecraft** at a
hundred. Full tables in [`research/results/`](research/results/).

Three findings worth the reader's time:

1. **Latency is set by the architecture, not by the attack.** It decomposes into
   two terms and neither is adversary behaviour: the tier a rule runs in (A2, A3
   and A4 detect at essentially the stream-path latency itself) and the rule's own
   threshold where evidence has to accumulate (A1 waits for five failed logons,
   A5 for twenty-five objects). Four of the five attacks show a confidence
   interval of zero across ten trials with randomised start times.
2. **Cryptographic integrity and physics-aware analytics are complementary.**
   Attack A3 disables frame authentication and then falsifies telemetry
   plausibly. After that point the only remaining detection is the one that
   reasons about the measurement itself.
3. **Detection without prevention is not a result.** A5 is detected in about four
   minutes, and roughly 24 objects (1.2 GB) still leave the account before
   containment. Turning the automated containment off leaves the detection
   latency identical and raises the exfiltrated volume to 13 GB. The paper
   reports what the response failed to prevent, not just what it saw.

## Repository layout

| Directory | Contents |
|---|---|
| [`architecture/`](architecture/) | Diagrams, trust boundaries, [threat model](architecture/threat-model.md) |
| [`satellite-simulator/`](satellite-simulator/) | Orbit, subsystem dynamics, telecommand handling |
| [`ground-station/`](ground-station/) | RF link, frame integrity, event normalization |
| [`cloud/`](cloud/) | Terraform for the AWS stack, detector and responder Lambdas |
| [`detection-rules/`](detection-rules/) | Rule catalogue and the portable Sigma pack |
| [`attack-scenarios/`](attack-scenarios/) | The five controlled attacks |
| [`incident-response/`](incident-response/) | One playbook per attack, NIST 800-61 phases |
| [`datasets/`](datasets/) | Labelled event log for reuse |
| [`research/`](research/) | Paper, experiment harness, results |
| [`src/spacelab/`](src/spacelab/) | The shared library every layer imports |

`src/spacelab/` is deliberately the single implementation: the deployed Lambda
imports the same rule pack the experiments measure, so results claimed for the
testbed are claimed for the deployed system too.

## Quick start

```bash
git clone https://github.com/rikosoo/space-ground-station-security-lab
cd space-ground-station-security-lab

python satellite-simulator/run.py --days 1     # orbit and telemetry sanity check
python ground-station/run.py --hours 24        # a nominal day, with the alert timeline
python -m pytest tests -q                      # 19 tests, ~14 s

python research/experiments/run_experiment.py all --trials 10
```

The last command regenerates every table in `research/results/` and the labelled
dataset in `datasets/`. It needs a few minutes and no network.

Deploying the cloud stack is optional and documented in
[`cloud/terraform/README.md`](cloud/terraform/README.md).

## The five attacks

| ID | Attack | Adversary capability | Kill chain |
|---|---|---|---|
| A1 | Credential compromise | Remote, credentialed | Password spray → session → in-role reconnaissance |
| A2 | Unauthorized command | Remote + RF | Hijacked session → critical command → out-of-window → forged frame |
| A3 | Telemetry tampering | Ground-segment foothold | Forged frames → disable frame auth → freeze a degrading channel |
| A4 | Replay | RF-capable | Capture a valid frame → re-transmit on later passes |
| A5 | Exfiltration | Compromised service principal | Bulk archive read → new access key → stop the audit trail |

Each scenario declares its own ground-truth label, so an alert counts as a true
positive only when an event it actually consumed was malicious — attribution by
causality, not by time proximity. Rules cannot read those labels, and a test
asserts it.

## Paper

[`research/paper/`](research/paper/) contains the LaTeX source of

> *A Cloud-Native Security Architecture for Detecting Cyber Threats in Satellite
> Ground Segments*

Build with `make -C research/paper` (needs `latexmk`). Every number in it comes
from `research/results/*.json` and is regenerated by the command above.

## Limitations

Stated plainly, because they bound what the numbers mean:

- The offline harness **models** pipeline latency instead of measuring it in AWS.
  The parameters that stand in for it are named and swept in
  `research/results/sweep.md`.
- The benign workload is synthetic. Its noise sources are realistic in kind
  (typos, roaming operators, link fades, a weekly bulk job) but their rates are
  chosen, not observed from a real mission.
- One spacecraft, one ground station, one cloud account. Multi-tenant
  ground-station-as-a-service isolation is out of scope and deserves its own
  study.
- Availability attacks such as jamming are excluded: they are detected by link
  metrics rather than by security telemetry, and mixing them in would confound
  the measurement.

## Licence

MIT. See [`LICENSE`](LICENSE).
