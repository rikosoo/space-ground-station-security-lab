# Threat model

## System under consideration

A single-spacecraft LEO mission (550 km, 53° inclination) operated through one
ground station, with mission control and all security analytics hosted in a
single cloud account. Three passes per day, each roughly seven minutes; the
vehicle is unreachable for about 97% of every day.

That last number drives everything. A ground segment is a system whose actuator
is available a few minutes a day, whose sensor stream arrives in bursts, and
whose adversary has the other 23 hours to work in.

## Assets

| Asset | Why an adversary wants it | Worst case |
|---|---|---|
| Telecommand authority | Direct control of a physical vehicle | Loss of the spacecraft |
| SDLS keys | Forge commands indefinitely | Persistent control, undetectable by tag checks |
| Telemetry integrity | Hide an effect, or induce a wrong operator decision | Operator-caused loss |
| Telemetry archive | Payload products, orbit data, mission intelligence | Disclosure, export-control violation |
| Audit trail | Cover for everything above | Loss of the ability to investigate at all |

## Adversary model

Three capability levels are used, and each scenario declares which it assumes:

* **N1 - remote, credentialed.** Phishing, credential stuffing, session relay.
  No RF capability. Covers A1, A5 and the API half of A2.
* **N2 - RF-capable.** Can receive and transmit on the mission's bands with a
  software-defined radio and knows the frame format. Cannot break HMAC-SHA256.
  Covers A4 and the RF half of A2.
* **N3 - ground-segment insider or footholded host.** Sits between the
  demodulator and cloud ingestion. Covers A3.

Out of scope: an adversary who obtains the SDLS key, breaks the cryptography, or
compromises the cloud provider's control plane. Those defeat the architecture by
assumption and would make the measurement uninteresting rather than pessimistic.

## Assumptions

1. Frame authentication keys are generated in and never leave a KMS-backed store.
2. The spacecraft's flight software enforces the anti-replay window; the ground
   segment cannot make it accept a stale frame.
3. Telemetry is archived before it is analysed, so detection never depends on the
   analytics tier being available in real time.
4. The detection pipeline itself is monitored (`IteratorAge`, `Errors`); a silent
   pipeline is treated as an outage, not as a quiet week.
5. Operators are a small, enumerable set, which is what makes origin profiling
   (R02) far more effective here than in a general enterprise.

## What this threat model deliberately does not cover

* Jamming and other availability attacks on the RF link. They are real and
  serious, but they are detected by link metrics rather than by security
  telemetry, and mixing them in would confound the measurement.
* Supply-chain compromise of the flight software.
* Physical attacks on the ground station.
* Multi-tenant ground-station-as-a-service isolation failures, which deserve
  their own study.
