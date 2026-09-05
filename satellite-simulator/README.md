# Satellite simulator

Models one spacecraft: circular-orbit propagation, ground-station visibility,
subsystem dynamics (power, thermal, attitude) and CCSDS-style telecommand
handling with SDLS-style frame authentication and an anti-replay window.

Implementation: [`src/spacelab/satellite/`](../src/spacelab/satellite/).

## What is modelled, and why only that

| Modelled | Reason |
|---|---|
| Two-body circular orbit | Pass windows, eclipse - the timing the detections depend on |
| Battery, bus current, temperatures, body rates, wheel speed | The physical envelopes that make falsified telemetry detectable |
| 13-command catalogue with a `critical` flag | Distinguishes routine operations from actions that endanger the vehicle |
| Frame authentication tag and sequence window | The two controls that actually stop A2 and A4 |

Not modelled: perturbations, manoeuvre dynamics, link budget in dB, real CCSDS
bit layouts. None of them change which events reach the SIEM, and each would add
error terms without adding evidence.

## Run it

```bash
python satellite-simulator/run.py --days 2
```

Prints pass geometry and a housekeeping telemetry sample, and writes nothing.
Use it to sanity-check orbit and subsystem behaviour before running experiments.
