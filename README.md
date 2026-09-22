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
is what makes hundred-trial confidence intervals affordable.

## Headline results

One hundred trials, each a 7-day baseline-learning window followed by a 7-day
measurement window containing all five attacks (about 5,700 events per window).
Regenerate with `python research/experiments/run_experiment.py all`.

| Attack | Detected | Median time to detect | p95 | First rule to fire | What stopped it |
|---|---|---|---|---|---|
| A1 Credential compromise | 100/100 | 48 s | 48 s | R01 brute force | Detecting the spray and revoking the account, before MFA was even tested |
| A2 Unauthorized command | 100/100 | 4 s | 5,924 s | R02 unprofiled origin (92), R05 uplink auth (8) | RBAC allowlist; SDLS tag for the RF variant |
| A3 Telemetry tampering | 100/100 | 14 s | 14 s | R06 frame integrity | Nothing prevented it; physics analytics caught the stealth phase |
| A4 Replay | 100/100 | 4 s | 4 s | R08 replay | Spacecraft anti-replay window |
| A5 Exfiltration | 100/100 | 246 s | 246 s | R09 bulk enumeration | Automated archive deny, after ~24 objects |

The median is the honest summary here, not the mean: A2's latency is bimodal and
its mean of 1,786 s describes no trial that actually happened. See finding 1.

False positives: **0.45 ± 0.04 per day**, precision **82.5%**. Modelled cost:
**~USD 420/month** for one spacecraft, falling to **~USD 80 per spacecraft** at a
hundred. Full tables in [`research/results/`](research/results/).

Three findings worth the reader's time:

1. **Latency is set by the architecture, not by the attack — and when it is not,
   the cause is our own response.** For four of the five attacks the latency
   decomposes into two terms and neither is adversary behaviour: the tier a rule
   runs in (A2, A3 and A4 detect at essentially the stream-path latency itself)
   and the rule's own threshold where evidence has to accumulate (A1 waits for
   five failed logons, A5 for twenty-five objects). Those four are tight across
   100 trials with randomised start times: A4 is identical every time, and A1, A3
   and A5 vary by ±0.5 s, ±0.3 s and ±2.3 s. A2 is bimodal, and the reason is
   worth more than the number. In 8 of 100 trials the operator account it targets
   was already blocked by an earlier automated response — usually one a false
   positive triggered days before — so the API refuses the session hijack
   *without emitting an authentication event at all*. With no logon to reason
   about, R02 has nothing to evaluate and detection falls through to R05 on the
   RF phase, which can only fire during a pass: up to 49,544 s. Containing one
   attack degraded the observability of the next. At this rate a ten-trial
   campaign misses the slow mode entirely about 43% of the time — which is
   exactly what the earlier ten-trial baseline did, reporting a confidence
   interval of zero for A2. The baseline now runs a hundred trials.
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

python research/experiments/run_experiment.py all
```

The last command regenerates every table in `research/results/` and the labelled
dataset in `datasets/`. It needs about fifteen minutes and no network; most of
that is the 100-trial baseline campaign, which `--baseline-trials` shortens for a
quick check. `--trials` controls the ablation and sweep, which report means and
are fine at ten.

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

The built PDF is committed at [`research/paper/main.pdf`](research/paper/main.pdf)
(11 pages) so it can be read without a TeX installation. Rebuild with
`make -C research/paper`, which needs `latexmk` plus `booktabs`, `siunitx` and
`balance`. Every number in the paper comes from `research/results/*.json` via
`make_macros.py`; none is typed by hand, so re-running the experiments and
rebuilding cannot leave a stale figure in the text.

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
