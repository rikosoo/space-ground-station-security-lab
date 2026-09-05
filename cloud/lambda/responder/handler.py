"""Containment Lambda (the SOAR step of the incident-response playbooks).

Triggered by ``SecurityAlert`` events on the security event bus. It performs the
containment actions defined in ``incident-response/playbooks`` and nothing more:
eradication and recovery stay with a human, because an automated action against
a spacecraft in flight can itself be the incident.

Every action is reversible and is recorded to DynamoDB so that the response
timeline can be reconstructed during the post-incident review.
"""

from __future__ import annotations

import datetime as dt
import json
import os
from typing import Any, Dict

try:
    import boto3
except ImportError:  # pragma: no cover
    boto3 = None

from spacelab.ir.responder import AUTO_CONTAIN_SEVERITIES, PLAYBOOK

USER_POOL_ID = os.environ.get("USER_POOL_ID", "")
QUARANTINE_POLICY_ARN = os.environ.get("QUARANTINE_POLICY_ARN", "")
UPLINK_PARAMETER = os.environ.get("UPLINK_PARAMETER", "/sgs/uplink/enabled")
ACTIONS_TABLE = os.environ.get("ACTIONS_TABLE", "sgs-response-actions")


def _record(action: str, entity: str, rule_id: str, applied: bool, note: str = "") -> None:
    payload = {
        "pk": f"{entity}#{dt.datetime.now(dt.timezone.utc).isoformat()}",
        "entity": entity, "action": action, "ruleId": rule_id,
        "applied": applied, "note": note,
    }
    print(json.dumps({"level": "response", **payload}))
    if boto3 is not None and ACTIONS_TABLE:
        boto3.resource("dynamodb").Table(ACTIONS_TABLE).put_item(Item=payload)


def _revoke_sessions(entity: str) -> None:
    if boto3 is None or not USER_POOL_ID:
        return
    boto3.client("cognito-idp").admin_user_global_sign_out(
        UserPoolId=USER_POOL_ID, Username=entity)


def _deny_archive(entity: str) -> None:
    if boto3 is None or not QUARANTINE_POLICY_ARN:
        return
    iam = boto3.client("iam")
    iam.attach_user_policy(UserName=entity.split("/")[-1],
                           PolicyArn=QUARANTINE_POLICY_ARN)


def _quarantine_uplink() -> None:
    if boto3 is None:
        return
    boto3.client("ssm").put_parameter(
        Name=UPLINK_PARAMETER, Value="false", Type="String", Overwrite=True)


def _restore_logging() -> None:
    if boto3 is None:
        return
    trail = os.environ.get("TRAIL_NAME", "sgs-audit")
    boto3.client("cloudtrail").start_logging(Name=trail)


def handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    detail = event.get("detail", event)
    rule_id, entity = detail.get("ruleId", "?"), detail.get("entity", "?")
    severity = detail.get("severity", "medium")
    action = PLAYBOOK.get(rule_id)

    if action is None:
        _record("none", entity, rule_id, False, "no playbook mapping")
        return {"applied": False}
    if severity not in AUTO_CONTAIN_SEVERITIES:
        _record(action, entity, rule_id, False, "queued for analyst review")
        return {"applied": False, "action": action}

    if action.startswith(("revoke_sessions", "block_principal")):
        _revoke_sessions(entity)
        _deny_archive(entity)
        if action.endswith("restore_logging"):
            _restore_logging()
    elif action == "deny_archive_access":
        _deny_archive(entity)
    elif action == "quarantine_uplink_path":
        _quarantine_uplink()
    elif action == "flag_telemetry_untrusted":
        if boto3 is not None:
            boto3.client("ssm").put_parameter(
                Name="/sgs/telemetry/trusted", Value="false", Type="String",
                Overwrite=True)
    _record(action, entity, rule_id, True)
    return {"applied": True, "action": action, "entity": entity}
