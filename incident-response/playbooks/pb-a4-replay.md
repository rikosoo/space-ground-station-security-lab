# PB-A4 - Telecommand replay

**Triggering detections:** R08 (replayed frame)
**Severity:** critical · **Automation:** quarantine uplink path · **Owner:** Flight Ops lead

## 1. Detection and analysis
1. Read `detected_by`, which determines the whole response:
   - `spacecraft_anti_replay` - the vehicle rejected it. The control worked; the
     event is intelligence about an adversary with RF capability, not a vehicle
     emergency.
   - `ground_duplicate_counter` - the ground station saw the same counter twice
     but the vehicle may have accepted it. Check the executed-command log.
   - `stale_frame_timestamp` - a downlink frame arrived far later than it was
     emitted; consider a recording-and-retransmission position on the downlink.
2. Establish which frame was replayed and what it does. A replayed `PING` is
   noise; a replayed `WHEEL_SPEED_SET` is a manoeuvre.
3. Estimate the adversary's capture window from the age of the replayed frame.
   It tells you how long they have been listening.

## 2. Containment
- Automated: uplink quarantined pending analysis.
- Manual: if the anti-replay window rejected the frame, containment can be
  lifted quickly - the vehicle defended itself.

## 3. Eradication and recovery
- Verify the anti-replay window is enabled and correctly sized on every security
  association. A window that is too wide tolerates replays; too narrow drops
  legitimate frames after reordering.
- Rotate keys if there is any evidence the adversary can produce *new* valid
  tags rather than only replay old frames.

## 4. Post-incident
- Replay capability implies RF proximity or access to a recording. Feed the pass
  geometry at capture time to whoever owns the physical-security question.
- This is the scenario where prevention and detection coincide: the same control
  that blocks the command also produces the alert. Note it in the metrics review.
