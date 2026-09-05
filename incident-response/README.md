# Incident response

Five playbooks, one per attack scenario, written to the NIST SP 800-61r2 phase
model (preparation, detection and analysis, containment, eradication and
recovery, post-incident activity) with one deliberate constraint added:

> **Only containment is automated, and only with reversible actions.**

A ground segment controls a vehicle that cannot be rebooted, re-imaged or taken
offline for maintenance. An automated action that safes a spacecraft in response
to a false positive causes a real mission outage - the response becomes the
incident. Everything past containment is therefore a human decision, and every
automated action is chosen so that a mistaken one costs an operator a few
minutes, not a mission.

## What is automated

| Rule | Containment action | Reversible by |
|---|---|---|
| R01, R03, R04 | Revoke sessions, attach quarantine deny policy | Detaching the policy |
| R02 | Require step-up authentication on next logon | Clearing the flag |
| R05, R06, R08 | Quarantine the uplink path (refuse to transmit) | Setting the SSM parameter back |
| R07 | Mark telemetry untrusted (banner in the console, no auto-FDIR action) | Clearing the flag |
| R09, R10 | Deny archive access for the principal | Detaching the policy |
| R11 | Block principal and restart audit logging | Detaching the policy |

Nothing in this table commands the spacecraft. The most aggressive action the
automation can take is to stop the ground segment from transmitting.

## Measured response performance

`research/results/baseline.md` reports mean time to contain alongside mean time
to detect; the gap between them is the fixed 20 s decision latency of the
responder plus the alert's own pipeline latency. The ablation table
(`research/results/ablation.md`) reports what still happened after containment
fired, which is the honest measure of whether the response mattered.

## Playbooks

- [`playbooks/pb-a1-credential-compromise.md`](playbooks/pb-a1-credential-compromise.md)
- [`playbooks/pb-a2-unauthorized-command.md`](playbooks/pb-a2-unauthorized-command.md)
- [`playbooks/pb-a3-telemetry-tampering.md`](playbooks/pb-a3-telemetry-tampering.md)
- [`playbooks/pb-a4-replay.md`](playbooks/pb-a4-replay.md)
- [`playbooks/pb-a5-data-exfiltration.md`](playbooks/pb-a5-data-exfiltration.md)
