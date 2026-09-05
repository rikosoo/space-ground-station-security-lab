"""Streaming detector Lambda.

Deployed instantiation of the same rules the experiments run offline. It is
subscribed to two sources so that one code path covers the whole ground segment:

* the Kinesis stream carrying normalized ground-station, API and telemetry
  events, and
* the EventBridge default bus, which delivers CloudTrail management events.

Findings are emitted to AWS Security Hub in ASFF and, in parallel, as a custom
CloudWatch metric so that an alarm can page on detection latency itself.

The rule pack is imported unchanged from the research package: keeping a single
implementation is what allows the numbers measured in the testbed to be claimed
for the deployed system.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
from typing import Any, Dict, List

try:  # boto3 is provided by the Lambda runtime
    import boto3
except ImportError:  # pragma: no cover - local unit tests
    boto3 = None

from spacelab.events import Event
from spacelab.siem.engine import DetectionConfig, DetectionEngine

REGION = os.environ.get("AWS_REGION", "us-east-1")
ACCOUNT_ID = os.environ.get("ACCOUNT_ID", "000000000000")
PRODUCT_ARN = f"arn:aws:securityhub:{REGION}:{ACCOUNT_ID}:product/{ACCOUNT_ID}/default"
METRIC_NAMESPACE = os.environ.get("METRIC_NAMESPACE", "SpaceGroundSegment/Detection")
RESPONSE_BUS = os.environ.get("RESPONSE_BUS", "sgs-security-bus")

SEVERITY_LABEL = {"low": 20, "medium": 50, "high": 70, "critical": 90}

# The engine is created at cold start so that windowed rules keep state across
# invocations of a warm container. Long-window rules additionally checkpoint to
# DynamoDB in production; see cloud/terraform/dynamodb.tf.
_ENGINE = DetectionEngine(DetectionConfig(
    stream_latency_s=0.0,   # real latency is measured, not modelled, in AWS
    batch_latency_s=0.0,
))


def _to_event(record: Dict[str, Any]) -> Event:
    if "kinesis" in record:
        body = json.loads(base64.b64decode(record["kinesis"]["data"]))
    else:  # EventBridge envelope for CloudTrail management events
        detail = record.get("detail", {})
        body = {
            "ts": _epoch(record.get("time")),
            "source": "cloud.audit",
            "event_type": f"{detail.get('eventSource','').split('.')[0]}:"
                          f"{detail.get('eventName','')}",
            "actor": (detail.get("userIdentity", {}) or {}).get("arn", "-"),
            "target": detail.get("requestParameters", {}) or "-",
            "outcome": "failure" if detail.get("errorCode") else "success",
            "src_ip": detail.get("sourceIPAddress", "-"),
            "attrs": {"user_agent": detail.get("userAgent", "-")},
        }
    body.setdefault("ground_truth", "benign")
    if isinstance(body.get("target"), dict):
        body["target"] = json.dumps(body["target"])[:200]
    return Event(**body)


def _epoch(iso: str | None) -> float:
    if not iso:
        return dt.datetime.now(dt.timezone.utc).timestamp()
    return dt.datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def _finding(alert) -> Dict[str, Any]:
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    return {
        "SchemaVersion": "2018-10-08",
        "Id": f"{alert.rule_id}/{alert.entity}/{int(alert.trigger_ts)}",
        "ProductArn": PRODUCT_ARN,
        "GeneratorId": f"sgs-detector/{alert.rule_id}",
        "AwsAccountId": ACCOUNT_ID,
        "Types": ["Unusual Behaviors/Application"],
        "CreatedAt": now,
        "UpdatedAt": now,
        "Severity": {"Label": alert.severity.upper(),
                     "Normalized": SEVERITY_LABEL.get(alert.severity, 50)},
        "Title": f"[{alert.rule_id}] {alert.rule_name}",
        "Description": json.dumps(alert.detail, default=str)[:1000],
        "Resources": [{"Type": "Other", "Id": alert.entity,
                       "Details": {"Other": {"technique": alert.technique,
                                             "tier": alert.tier}}}],
        "RecordState": "ACTIVE",
        "Workflow": {"Status": "NEW"},
        "UserDefinedFields": {"ruleId": alert.rule_id, "entity": alert.entity,
                              "triggerTs": str(alert.trigger_ts)},
    }


def handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    records: List[Dict[str, Any]] = event.get("Records") or [event]
    alerts = []
    for record in records:
        try:
            before = len(_ENGINE.alerts)
            _ENGINE.consume(_to_event(record))
            alerts.extend(_ENGINE.alerts[before:])
        except Exception as exc:  # a malformed record must not stop the stream
            print(json.dumps({"level": "error", "msg": "record_failed",
                              "error": str(exc)}))

    if alerts and boto3 is not None:
        sh, cw, eb = (boto3.client("securityhub"), boto3.client("cloudwatch"),
                      boto3.client("events"))
        findings = [_finding(a) for a in alerts]
        for i in range(0, len(findings), 100):
            sh.batch_import_findings(Findings=findings[i:i + 100])
        cw.put_metric_data(
            Namespace=METRIC_NAMESPACE,
            MetricData=[{"MetricName": "Alerts", "Value": len(alerts), "Unit": "Count"}]
            + [{"MetricName": "AlertsByRule", "Value": 1, "Unit": "Count",
                "Dimensions": [{"Name": "RuleId", "Value": a.rule_id}]} for a in alerts],
        )
        eb.put_events(Entries=[{
            "EventBusName": RESPONSE_BUS,
            "Source": "sgs.detector",
            "DetailType": "SecurityAlert",
            "Detail": json.dumps({"ruleId": a.rule_id, "severity": a.severity,
                                  "entity": a.entity, "detail": a.detail},
                                 default=str),
        } for a in alerts])

    for a in alerts:  # structured logs for the analytics tier
        print(json.dumps({"level": "alert", "ruleId": a.rule_id,
                          "severity": a.severity, "entity": a.entity,
                          "technique": a.technique, "detail": a.detail}, default=str))
    return {"processed": len(records), "alerts": len(alerts)}
