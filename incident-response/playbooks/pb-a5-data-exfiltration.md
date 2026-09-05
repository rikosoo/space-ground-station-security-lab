# PB-A5 - Mission data exfiltration

**Triggering detections:** R09 (bulk enumeration), R10 (volume anomaly), R11 (control-plane tampering)
**Severity:** high to critical · **Automation:** deny archive access; restore logging · **Owner:** SOC analyst, escalate to data owner

## 1. Detection and analysis
1. Identify the principal and whether it is human. A service principal reading
   at machine speed from an unfamiliar network is the common case and the one
   MFA cannot help with.
2. Quantify: distinct objects, total bytes, time window, source address, user
   agent. `s3-sync`-style agents are not what the mission's own pipelines use.
3. Check for control-plane activity **after** the reads (`StopLogging`,
   `CreateAccessKey`). An adversary who covers tracks afterwards leaves a much
   later signal than one who does it first - do not assume the earliest alert is
   the earliest activity.
4. Establish what was in the objects read. Raw housekeeping telemetry, payload
   products and orbit determination products carry very different consequences.

## 2. Containment (automated)
- Quarantine deny policy attached to the principal; audit logging restarted if
  it was stopped.
- Analyst confirms no successful `GetObject` after the containment timestamp.

## 3. Eradication and recovery
- Delete access keys created by the adversary; rotate the principal's remaining
  credentials.
- Review the bucket policy and any presigned URLs issued in the window.
- If logging was stopped, treat the gap as unobservable and reconstruct activity
  from S3 server access logs and application-side records.

## 4. Post-incident
- Compare the incident against the legitimate weekly reprocessing job, which
  produces a superficially identical access pattern. If the rule cannot separate
  them, exclude that principal by ARN and alert instead on that principal
  reading from an unexpected origin - never widen the threshold, which is what
  makes the rule stop working.
- Report volumes to the data owner and, for export-controlled or
  customer-owned data, to whoever holds the notification obligation.
