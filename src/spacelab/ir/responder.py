"""Automated containment (the SOAR half of detection engineering).

In the deployed architecture this is a Lambda subscribed to the EventBridge bus
that Security Hub findings land on. It implements the containment step of each
playbook in ``incident-response/playbooks``; anything beyond containment
(eradication, recovery, lessons learned) stays human-owned by design, because
irreversible actions on a flight system must not be automated.

The responder is instrumented so the experiment can report **mean time to
contain** alongside mean time to detect, and can measure how many malicious
actions still succeeded after containment fired.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from ..events import SRC_IR, Event
from ..siem.engine import Alert

#: rule -> containment action. Actions are intentionally reversible.
PLAYBOOK: Dict[str, str] = {
    "R01": "revoke_sessions_and_block_principal",
    "R02": "require_step_up_auth",
    "R03": "block_principal",
    "R04": "block_principal",
    "R05": "quarantine_uplink_path",
    "R06": "quarantine_uplink_path",
    "R07": "flag_telemetry_untrusted",
    "R08": "quarantine_uplink_path",
    "R09": "deny_archive_access",
    "R10": "deny_archive_access",
    "R11": "block_principal_and_restore_logging",
}

#: Only these severities are contained automatically; the rest are queued for a
#: human analyst. This threshold is one of the parameters swept in the study.
AUTO_CONTAIN_SEVERITIES = {"high", "critical"}


@dataclass
class ResponseAction:
    ts: float
    alert_rule: str
    action: str
    entity: str
    automated: bool


@dataclass
class AutomatedResponder:
    world: object
    bus: object
    decision_latency_s: float = 20.0
    actions: List[ResponseAction] = field(default_factory=list)
    contained_entities: set = field(default_factory=set)
    enabled: bool = True

    def handle(self, alert: Alert) -> None:
        if not self.enabled:
            return
        action = PLAYBOOK.get(alert.rule_id)
        if action is None:
            return
        automated = alert.severity in AUTO_CONTAIN_SEVERITIES
        t = alert.ts + self.decision_latency_s
        if automated:
            self._apply(action, alert.entity, t)
            self.contained_entities.add(alert.entity)
        self.actions.append(ResponseAction(t, alert.rule_id, action, alert.entity, automated))
        self.bus.publish(
            Event(
                ts=t, source=SRC_IR, event_type="response.action",
                actor="soar-lambda", target=alert.entity,
                attrs={
                    "action": action, "automated": automated,
                    "rule_id": alert.rule_id, "severity": alert.severity,
                    "alert_ts": alert.ts,
                },
            )
        )

    # ------------------------------------------------------------- actions
    def _apply(self, action: str, entity: str, t: float) -> None:
        w = self.world
        if action in {
            "revoke_sessions_and_block_principal", "block_principal",
            "block_principal_and_restore_logging",
        }:
            w.api.blocked_principals.add(entity, t)
            for tok, s in list(w.api.sessions.items()):
                if s.user_id == entity:
                    del w.api.sessions[tok]
            w.archive.blocked_principals.add(entity, t)
            if action.endswith("restore_logging"):
                w.iam.logging_enabled = True
        elif action == "deny_archive_access":
            w.archive.blocked_principals.add(entity, t)
        elif action == "quarantine_uplink_path":
            w.uplink_quarantined = True
        elif action == "flag_telemetry_untrusted":
            w.telemetry_trusted = False
        elif action == "require_step_up_auth":
            w.step_up_required.add(entity)
