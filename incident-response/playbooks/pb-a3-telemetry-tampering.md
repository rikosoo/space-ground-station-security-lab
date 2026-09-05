# PB-A3 - Telemetry tampering (false data injection)

**Triggering detections:** R06 (clustered integrity failures), R07 (physics violation), R11 (frame authentication disabled)
**Severity:** high to critical · **Automation:** quarantine uplink, mark telemetry untrusted · **Owner:** Flight Ops lead

The danger here is not the falsified value; it is the decision an operator makes
because of it. The first containment action is therefore epistemic: stop trusting
the data.

## 1. Detection and analysis
1. Check whether frame authentication is still enabled. If R11 fired on
   `TLM_AUTH_DISABLE`, treat **all** telemetry received after that timestamp as
   unverified regardless of how plausible it looks.
2. For R06, separate link noise from injection: correlate `attrs.elevation_deg`
   and `attrs.channel_corrupted`. Failures clustered at high elevation are not
   the radio.
3. For R07, identify the channel and the violation kind:
   - `out_of_envelope` / `rate_violation` - crude injection, easy to spot;
   - `stuck_channel` - masking. Ask what the frozen value is hiding and check
     the same subsystem's *other* channels, which the adversary may not have
     bothered to freeze consistently.
4. Rebuild the true subsystem state from the last frames whose tags verified.

## 2. Containment
- Automated: telemetry marked untrusted (console banner, automatic FDIR
  responses suspended); uplink quarantined.
- Manual: re-enable frame authentication on the next pass with a signed command,
  and verify that tags verify again before lifting the untrusted flag.

## 3. Eradication and recovery
- Find the injection point. Between the demodulator and the ingestion endpoint
  is a short list of hosts; treat every one as compromised until cleared.
- Rotate the telemetry security association key.
- Re-derive any operational decision made from tampered telemetry - in
  particular, any manoeuvre planned against a falsified power or attitude state.

## 4. Post-incident
- Record the interval between the first injected frame and the operator's loss
  of trust. That interval, not the alert latency, is the real exposure.
- If the stealth phase was only caught by physics analytics, that is direct
  evidence for keeping content-based detections alongside cryptographic ones.
