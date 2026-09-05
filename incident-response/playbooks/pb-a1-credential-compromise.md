# PB-A1 - Compromised operator credentials

**Triggering detections:** R01 (brute force then success), R02 (unprofiled origin)
**Severity:** high · **Automation:** revoke sessions + quarantine policy · **Owner:** SOC analyst, escalate to Flight Ops lead

## 1. Preparation
- Every operator account is in the identity provider with hardware-backed MFA;
  service principals that cannot hold MFA are enumerated and treated as
  higher-risk by policy (see A5).
- Baseline window of at least seven days exists for R02; a new operator has no
  profile and will generate one expected alert on their first session.

## 2. Detection and analysis
1. Read the finding: `actor`, `src_ip`, `attrs.asn`, `attrs.user_agent`,
   `failed_attempts`.
2. Decide the branch:
   - **Failures only, no success** - the second factor held. Treat as attempted
     compromise; the credential is still burned and must be rotated.
   - **Failures then success** - assume compromise, continue.
   - **Success with no preceding failures but a new origin** (R02 alone) - check
     for a relayed session (`attrs.auth_method: session_token_replay`), which
     indicates adversary-in-the-middle phishing rather than a guessed password.
3. Pull every action taken by the account since the first suspicious event:
   commands submitted, archive objects read, control-plane calls.

## 3. Containment (automated)
- All sessions for the principal are revoked and the quarantine deny policy is
  attached, within roughly 20 s of the alert.
- Analyst verifies containment took effect: no events from the principal after
  the containment timestamp.

## 4. Eradication and recovery
- Rotate the credential and any API keys the principal held.
- If a session-token replay is indicated, invalidate refresh tokens pool-wide;
  rotating a password does not kill a stolen session.
- Re-enable the account only after the operator re-enrols their second factor
  out of band.

## 5. Post-incident
- If the account issued any telecommand, hand the list to Flight Ops for a
  vehicle-state review even when every command was in-role.
- Record whether MFA blocked the logon. That single fact is the strongest
  evidence for or against the account-security investment.
