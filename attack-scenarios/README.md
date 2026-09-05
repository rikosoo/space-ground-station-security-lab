# Attack scenarios

Five controlled attacks, each a Python module exposing a `SCENARIO` object. They
run entirely inside the testbed, declare their own ground-truth label so scoring
is unambiguous, and record the simulated time of their first malicious action —
the reference point for every latency measurement in the paper.

| File | ID | Adversary | What it does |
|---|---|---|---|
| `a1_credential_compromise.py` | A1 | N1 remote, credentialed | Password spray from a foreign ASN, then a session and in-role reconnaissance |
| `a2_unauthorized_command.py` | A2 | N1 + N2 | Hijacked session issues critical commands, one outside any pass window, then forged frames injected at RF |
| `a3_telemetry_tampering.py` | A3 | N3 ground-segment foothold | Crude forged frames, then disables frame authentication and freezes a degrading channel |
| `a4_replay.py` | A4 | N2 radio-capable | Captures a valid authenticated frame and re-transmits it on later passes |
| `a5_data_exfiltration.py` | A5 | N1 service principal | Bulk-reads the archive, mints an access key, then stops the audit trail |

Capability levels N1–N3 are defined in
[`architecture/threat-model.md`](../architecture/threat-model.md).

## Design notes

**Ordering is part of the experiment.** A5 exfiltrates *before* it covers its
tracks. An adversary who stops the audit trail first is caught in seconds by the
control-plane rule; putting the anti-forensics last forces the data-plane
analytics to do the work, which is the harder and more realistic case.

**A2 and A3 assume a relayed second factor**, not a guessed password. This keeps
the MFA ablation meaningful: MFA genuinely prevents A1, and a scenario in which
it also prevented everything else would measure nothing about detection.

**A4's reference time is the first re-transmission**, not the radio capture.
Passive capture leaves no observable in the ground segment, and measuring
latency from an event no defender could ever see would understate detection
unfairly.

## Running one on its own

```python
from spacelab.experiment import TrialConfig, run_trial

result = run_trial(TrialConfig(seed=42, warmup_days=5, measure_days=3,
                               scenario_ids=["A3"]))
print(result.outcomes["A3"])
```

## Adding a scenario

Subclass `Scenario` (see [`src/spacelab/attacks.py`](../src/spacelab/attacks.py)),
schedule actions with `world.at(t, fn)`, pass `ground_truth=self.id` to every
call that emits an event, and expose the instance as `SCENARIO`. Files matching
`a[1-9]_*.py` are discovered automatically.
