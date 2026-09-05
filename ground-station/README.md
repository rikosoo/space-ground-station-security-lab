# Ground station

The RF front-end and frame processor, plus the agent that normalizes everything
it sees into the shared event schema and ships it to the cloud.

Implementation: [`src/spacelab/groundstation/`](../src/spacelab/groundstation/).

## Responsibilities

1. **Link availability.** A telecommand only reaches the vehicle while it is
   above the mask angle (10° by default). Submissions outside a pass are refused
   and logged - the observable behind detection R04's timing variant.
2. **Link noise.** Frames are corrupted with a probability that rises sharply at
   low elevation. This is the dominant benign source of integrity failures and
   therefore the main driver of the measured false-positive rate; a testbed
   without it would report a false-positive rate of zero and prove nothing.
3. **Integrity checking.** Every downlinked frame's authentication tag is
   verified. Frames arriving without a tag are marked `not_verified` rather than
   silently accepted, because "authentication was switched off" and
   "authentication failed" are different incidents.
4. **Normalization.** Everything becomes an `Event` (see
   [`src/spacelab/events.py`](../src/spacelab/events.py)) and goes on the bus -
   in AWS, into Kinesis.

## Run it

```bash
python ground-station/run.py --hours 12
```

Runs a nominal shift: passes, telemetry, operator logins, routine commands, and
prints the alert timeline the SIEM produced.
