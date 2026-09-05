# PB-A2 - Unauthorized telecommand

**Triggering detections:** R03 (RBAC violation), R04 (unusual critical command), R05 (uplink rejected)
**Severity:** high to critical · **Automation:** block principal; quarantine uplink on R05 · **Owner:** Flight Ops lead with SOC analyst

This is the only playbook where the vehicle itself may be affected. Treat it as
a joint security and flight-safety event from the first minute.

## 1. Detection and analysis
1. Determine which layer refused the command, because it tells you where the
   adversary is:
   - **R03 with `blocked: true`** - the API refused it. The adversary is at the
     application layer with valid credentials.
   - **R04 without R03** - the command was within the role's allowlist but
     outside the principal's history. Entitlement is too broad; treat as abuse.
   - **R05** - the *spacecraft* refused it. A frame reached the antenna that
     mission control did not sign: the adversary is at or past the ground
     station, not at the API.
2. Reconstruct vehicle state: query the executed-command log for the pass and
   compare against the approved pass plan.
3. Check for out-of-window submissions (`reason: outside_pass_window`) - a
   strong indicator of scripted rather than human operation.

## 2. Containment (automated, then manual)
- Automated: principal blocked; on R05 the uplink path is quarantined so the
  station stops transmitting.
- Manual: Flight Ops confirms whether any critical command executed. If one did,
  open a flight-safety event in parallel with the security incident.

## 3. Eradication and recovery
- Rotate the SDLS key for the affected security association if R05 fired; assume
  key exposure until proven otherwise.
- Re-narrow the role allowlist that permitted the command, if R04 fired without
  R03.
- Lift the uplink quarantine only after a signed test command is verified
  end-to-end on a rehearsal pass.

## 4. Post-incident
- Every R05 event is a reportable anomaly to the licensing authority in most
  jurisdictions; check the mission's regulatory obligations.
- Review whether the pass-window check should be enforcing rather than
  advisory - it costs nothing and removes an entire attack variant.
