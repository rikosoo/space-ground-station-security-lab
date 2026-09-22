"""Detection content.

Each rule maps to a technique in the SPARTA matrix for space systems and, where
applicable, to its terrestrial ATT&CK analogue. The identifiers are reused
verbatim in ``detections/sigma`` so the same logic can be deployed to a real
log-analytics backend, and in the paper's detection-coverage table.

Rules are deliberately of three kinds, because the evaluation compares them:

* **deterministic policy rules** (R03, R05, R07, R10, R11) - a violation of a
  control that should never occur in nominal operations,
* **thresholded rules** (R01, R05, R09) - noisy signals aggregated over a window,
* **behavioural/statistical rules** (R02, R04, R08) - deviation from a profile
  learned during a warm-up window.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional

from ..events import OUTCOME_FAILURE, OUTCOME_SUCCESS, Event
from ..satellite.simulator import COMMAND_CATALOG, TELEMETRY_ENVELOPE
from .engine import Alert


class Rule:
    id: str = "R00"
    name: str = "base"
    severity: str = "medium"
    technique: str = "-"
    tier: str = "stream"

    def __init__(self, engine) -> None:
        self.engine = engine
        self.cfg = engine.config
        self.setup()

    def setup(self) -> None:  # pragma: no cover - overridden when needed
        pass

    def evaluate(self, event: Event) -> Optional[List[Alert]]:
        raise NotImplementedError

    def tick(self, now: float) -> Optional[List[Alert]]:
        """Evaluate anything that is due on the clock rather than on an event.

        Batch-tier rules that aggregate over a fixed window run as a scheduled
        job in the deployed system, so their window has to close on time even
        when the principal they are aggregating has stopped producing events --
        which is exactly what automated containment causes.
        """
        return None

    def alert(self, entity: str, event: Event, evidence: List[Event],
              at: Optional[float] = None, **detail) -> Alert:
        trigger = event.ts if at is None else at
        return Alert(
            ts=trigger + self.engine.latency_for(self.tier),
            trigger_ts=trigger,
            rule_id=self.id,
            rule_name=self.name,
            severity=self.severity,
            entity=entity,
            technique=self.technique,
            tier=self.tier,
            evidence=list(evidence),
            detail=detail,
        )


# --------------------------------------------------------------------- R01
class BruteForceThenSuccess(Rule):
    id, name = "R01", "Credential brute force followed by successful logon"
    severity, technique, tier = "high", "SPARTA REC-0005 / ATT&CK T1110", "stream"

    def setup(self) -> None:
        self.fails: Dict[str, Deque[Event]] = defaultdict(deque)

    def evaluate(self, event):
        if event.event_type != "auth.login":
            return None
        q = self.fails[event.actor]
        while q and q[0].ts < event.ts - self.cfg.auth_fail_window_s:
            q.popleft()
        if event.outcome == OUTCOME_FAILURE:
            q.append(event)
            # A burst of failures is actionable on its own: when a second factor
            # blocks the adversary, the successful logon that would otherwise
            # confirm the compromise never arrives.
            if len(q) == self.cfg.auth_fail_threshold:
                return [self.alert(event.actor, event, list(q),
                                   failed_attempts=len(q), src_ip=event.src_ip,
                                   followed_by_success=False)]
            return None
        if len(q) >= self.cfg.auth_fail_threshold:
            evidence = list(q) + [event]
            q.clear()
            return [self.alert(event.actor, event, evidence,
                               failed_attempts=len(evidence) - 1,
                               src_ip=event.src_ip, followed_by_success=True)]
        return None


# --------------------------------------------------------------------- R02
class AnomalousSessionOrigin(Rule):
    id, name = "R02", "Successful logon from unprofiled network origin"
    severity, technique, tier = "medium", "SPARTA IA-0004 / ATT&CK T1078", "stream"

    def evaluate(self, event):
        if event.event_type != "auth.login" or event.outcome != OUTCOME_SUCCESS:
            return None
        b = self.engine.baseline
        user, ip = event.actor, event.src_ip
        asn = event.attrs.get("asn", "-")
        agent = event.attrs.get("user_agent", "-")
        if self.cfg.learning:
            b.observe_login(user, ip, asn, agent)
            return None
        known_asn = asn in b.known_asns.get(user, set())
        known_agent = agent in b.known_agents.get(user, set())
        if known_asn and known_agent:
            return None
        return [self.alert(user, event, [event], asn=asn, src_ip=ip,
                           user_agent=agent, new_asn=not known_asn,
                           new_user_agent=not known_agent)]


# --------------------------------------------------------------------- R03
class RbacViolation(Rule):
    id, name = "R03", "Telecommand outside the principal's authorized set"
    severity, technique, tier = "high", "SPARTA EX-0012 / ATT&CK T1078.004", "stream"

    def evaluate(self, event):
        if event.event_type != "command.submit":
            return None
        reason = event.attrs.get("reason")
        if reason == "rbac_denied":
            return [self.alert(event.actor, event, [event],
                               command=event.attrs.get("command"),
                               role=event.attrs.get("role"), blocked=True)]
        # RBAC disabled (ablation): catch the authorized-but-illegitimate case
        from ..api.app import ROLE_PERMISSIONS

        role = event.attrs.get("role", "-")
        cmd = event.attrs.get("command", "-")
        if (
            event.outcome == OUTCOME_SUCCESS
            and role in ROLE_PERMISSIONS
            and cmd not in ROLE_PERMISSIONS[role]
        ):
            return [self.alert(event.actor, event, [event], command=cmd,
                               role=role, blocked=False)]
        return None


# --------------------------------------------------------------------- R04
class UnusualCriticalCommand(Rule):
    id, name = "R04", "Critical telecommand by a principal with no such history"
    severity, technique, tier = "high", "SPARTA EX-0009", "stream"

    def evaluate(self, event):
        if event.event_type != "command.submit":
            return None
        cmd = event.attrs.get("command", "-")
        spec = COMMAND_CATALOG.get(cmd)
        if not spec or not spec["critical"]:
            return None
        b = self.engine.baseline
        if self.cfg.learning:
            b.critical_command_users.add(event.actor)
            return None
        if event.actor in b.critical_command_users:
            return None
        return [self.alert(event.actor, event, [event], command=cmd,
                           outcome=event.outcome,
                           session_age_s=event.attrs.get("session_age_s"))]


# --------------------------------------------------------------------- R05
class UplinkAuthenticationFailure(Rule):
    id, name = "R05", "Telecommand rejected by the spacecraft SDLS check"
    severity, technique, tier = "critical", "SPARTA IA-0008 / EX-0016", "stream"

    def evaluate(self, event):
        if event.event_type != "uplink.transmit":
            return None
        if event.attrs.get("reason") not in {"auth_tag_invalid", "unknown_command"}:
            return None
        return [self.alert(event.target, event, [event],
                           reason=event.attrs.get("reason"),
                           command=event.attrs.get("command"),
                           src_ip=event.src_ip, submitted_by=event.actor)]


# --------------------------------------------------------------------- R06
class DownlinkIntegrityAnomaly(Rule):
    id, name = "R06", "Clustered telemetry frame integrity failures"
    severity, technique, tier = "high", "SPARTA EXF-0006 / IMP-0002", "stream"

    def setup(self) -> None:
        self.window: Deque[Event] = deque()

    def evaluate(self, event):
        if event.event_type != "downlink.frame":
            return None
        if event.attrs.get("integrity") in ("ok", "not_verified"):
            return None
        self.window.append(event)
        while self.window and self.window[0].ts < event.ts - self.cfg.integrity_window_s:
            self.window.popleft()
        if len(self.window) < self.cfg.integrity_threshold:
            return None
        evidence = list(self.window)
        return [self.alert(event.actor, event, evidence,
                           failures_in_window=len(evidence),
                           window_s=self.cfg.integrity_window_s)]


# --------------------------------------------------------------------- R07
class TelemetryPhysicsViolation(Rule):
    """Catches tampering that survives the cryptographic check.

    Two independent checks: an out-of-envelope or physically impossible rate of
    change, and a *stuck* channel (a constant value across many samples), which
    is the signature of a masking attack that freezes a degrading measurement.
    """

    id, name = "R07", "Telemetry inconsistent with subsystem physics"
    severity, technique, tier = "high", "SPARTA IMP-0002", "batch"
    STUCK_SAMPLES = 12

    def setup(self) -> None:
        # Each channel keeps its previous sample *and the event that carried it*,
        # because a rate violation is a statement about a pair of samples: an
        # alert that cites only the second one gives the analyst half the
        # evidence, and would attribute the alert to the wrong activity.
        self.prev: Dict[str, tuple[float, float, Event]] = {}
        self.hist: Dict[str, Deque[tuple[float, Event]]] = defaultdict(
            lambda: deque(maxlen=self.STUCK_SAMPLES))

    def evaluate(self, event):
        if event.event_type != "telemetry.sample":
            return None
        if event.attrs.get("integrity_ok") is False:
            # A frame that already failed its authentication tag is a link or
            # forgery problem and belongs to R06. Running content analytics on
            # bits known to be corrupt only manufactures false positives: every
            # false positive this rule produced before the exclusion came from a
            # frame the integrity check had already rejected.
            return None

        hits = []
        evidence = {id(event): event}
        for chan, (lo, hi, max_rate) in TELEMETRY_ENVELOPE.items():
            if chan not in event.attrs:
                continue
            val = float(event.attrs[chan])
            key = f"{event.actor}:{chan}"

            if val < lo or val > hi:
                hits.append((chan, val, "out_of_envelope"))

            prev = self.prev.get(key)
            if prev is not None:
                dt = max(event.ts - prev[1], 1e-6)
                if abs(val - prev[0]) / dt > max_rate:
                    hits.append((chan, val, "rate_violation"))
                    evidence[id(prev[2])] = prev[2]
            self.prev[key] = (val, event.ts, event)

            h = self.hist[key]
            h.append((val, event))
            # A channel resting against a physical rail (a full battery in
            # sunlight, a saturated wheel) is legitimately constant; excluding
            # the rails removes the dominant false positive of this rule.
            at_rail = abs(val - lo) < 1e-6 or abs(val - hi) < 1e-6
            values = [v for v, _ in h]
            if (
                len(h) == self.STUCK_SAMPLES and max(values) == min(values)
                and not at_rail and chan.startswith(("battery", "temp", "bus"))
            ):
                hits.append((chan, val, "stuck_channel"))
                for _, ev in h:
                    evidence[id(ev)] = ev
                h.clear()

        if not hits:
            return None
        return [self.alert(event.actor, event, list(evidence.values()),
                           violations=[{"channel": c, "value": v, "kind": k}
                                       for c, v, k in hits])]


# --------------------------------------------------------------------- R08
class ReplayDetected(Rule):
    id, name = "R08", "Replayed telecommand frame"
    severity, technique, tier = "critical", "SPARTA EX-0013 / ATT&CK T1499", "stream"
    STALE_S = 60.0

    def setup(self) -> None:
        self.seen_seq: Dict[str, float] = {}

    def evaluate(self, event):
        if event.event_type == "uplink.transmit":
            seq = event.attrs.get("seq")
            reason = event.attrs.get("reason")
            if reason == "replay_window_reject":
                return [self.alert(event.target, event, [event], seq=seq,
                                   detected_by="spacecraft_anti_replay")]
            key = f"{event.target}:TC:{seq}"
            if seq is not None and key in self.seen_seq:
                first = self.seen_seq[key]
                return [self.alert(event.target, event, [event], seq=seq,
                                   detected_by="ground_duplicate_counter",
                                   first_seen_ts=first,
                                   delta_s=round(event.ts - first, 1))]
            if seq is not None:
                self.seen_seq[key] = event.ts
        elif event.event_type == "downlink.frame":
            latency = event.attrs.get("latency_s", 0.0)
            if latency > self.STALE_S:
                return [self.alert(event.actor, event, [event],
                                   detected_by="stale_frame_timestamp",
                                   latency_s=latency, seq=event.attrs.get("seq"))]
        return None


# --------------------------------------------------------------------- R09
class ArchiveMassEnumeration(Rule):
    id, name = "R09", "Bulk enumeration of the telemetry archive"
    severity, technique, tier = "high", "SPARTA EXF-0008 / ATT&CK T1530", "batch"

    def setup(self) -> None:
        self.window: Dict[str, Deque[Event]] = defaultdict(deque)

    def evaluate(self, event):
        if event.event_type != "s3.GetObject" or event.outcome != OUTCOME_SUCCESS:
            return None
        q = self.window[event.actor]
        q.append(event)
        while q and q[0].ts < event.ts - self.cfg.exfil_window_s:
            q.popleft()
        distinct = {e.attrs.get("key") for e in q}
        if len(distinct) < self.cfg.exfil_key_threshold:
            return None
        evidence = list(q)
        q.clear()
        return [self.alert(event.actor, event, evidence,
                           distinct_keys=len(distinct),
                           bytes=sum(e.attrs.get("bytes", 0) for e in evidence),
                           window_s=self.cfg.exfil_window_s)]


# --------------------------------------------------------------------- R10
class ArchiveVolumeAnomaly(Rule):
    id, name = "R10", "Archive read volume far above the principal's baseline"
    severity, technique, tier = "medium", "SPARTA EXF-0007", "batch"
    BUCKET_S = 3600.0

    def setup(self) -> None:
        self.bucket_start: Dict[str, float] = {}
        self.bucket_bytes: Dict[str, float] = defaultdict(float)
        self.bucket_events: Dict[str, List[Event]] = defaultdict(list)

    def evaluate(self, event):
        if event.event_type != "s3.GetObject" or event.outcome != OUTCOME_SUCCESS:
            return None
        p = event.actor
        self.bucket_start.setdefault(p, event.ts)
        self.bucket_bytes[p] += event.attrs.get("bytes", 0)
        self.bucket_events[p].append(event)
        return None

    def tick(self, now: float):
        """Close every bucket whose hour has elapsed.

        Closing on the clock rather than on the principal's next read is what
        makes this rule able to report the burst it exists to detect: once R09
        fires and the responder denies the principal, no further read arrives,
        and a bucket that waits for one is never evaluated at all.
        """
        out = []
        for p, start in list(self.bucket_start.items()):
            if now - start < self.BUCKET_S:
                continue
            alerts = self._close_bucket(p, at=start + self.BUCKET_S)
            if alerts:
                out.extend(alerts)
            # Keep the buckets aligned to the original grid, skipping any whole
            # hours in which the principal read nothing at all.
            elapsed = now - start
            self.bucket_start[p] = start + (elapsed // self.BUCKET_S) * self.BUCKET_S
        return out or None

    def _close_bucket(self, p: str, at: float):
        total = self.bucket_bytes.pop(p, 0.0)
        evidence = self.bucket_events.pop(p, [])
        # An hour in which the principal read nothing is not a sample of its
        # read volume, and counting it as one would drag the baseline mean
        # towards zero for every principal that works in bursts.
        if not evidence:
            return None
        b = self.engine.baseline
        if self.cfg.learning:
            b.read_bytes_hourly.setdefault(p, []).append(total)
            return None
        mean, std = b.stats(p)
        if std <= 0:
            return None
        z = (total - mean) / std
        if z < self.cfg.exfil_zscore:
            return None
        return [self.alert(p, evidence[-1], evidence, at=at, bytes=total,
                           baseline_mean=round(mean, 1), zscore=round(z, 2))]


# --------------------------------------------------------------------- R11
class ControlPlaneTampering(Rule):
    id, name = "R11", "Security control disabled or weakened"
    severity, technique, tier = "critical", "SPARTA DE-0002 / ATT&CK T1562", "stream"
    WATCH = {
        "cloudtrail:StopLogging",
        "s3:PutBucketPolicy",
        "iam:CreateAccessKey",
        "kms:ScheduleKeyDeletion",
    }

    def evaluate(self, event):
        if event.event_type in self.WATCH:
            return [self.alert(event.actor, event, [event],
                               action=event.event_type, target=event.target,
                               **{k: v for k, v in event.attrs.items() if k != "args"})]
        if (
            event.event_type == "command.submit"
            and event.attrs.get("command") == "TLM_AUTH_DISABLE"
        ):
            return [self.alert(event.actor, event, [event],
                               action="TLM_AUTH_DISABLE",
                               outcome=event.outcome)]
        return None


ALL_RULES = [
    BruteForceThenSuccess,
    AnomalousSessionOrigin,
    RbacViolation,
    UnusualCriticalCommand,
    UplinkAuthenticationFailure,
    DownlinkIntegrityAnomaly,
    TelemetryPhysicsViolation,
    ReplayDetected,
    ArchiveMassEnumeration,
    ArchiveVolumeAnomaly,
    ControlPlaneTampering,
]

RULE_INDEX = {r.id: r for r in ALL_RULES}
