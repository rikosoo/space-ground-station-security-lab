"""Normalized event schema shared by every layer of the testbed.

The schema is a deliberately small subset of the OCSF/ECS common model: enough
fields to write portable detections, few enough to keep the paper's data
dictionary on a single page. Every component emits :class:`Event` objects onto
the :class:`~spacelab.bus.EventBus`; the SIEM consumes them unchanged.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, Dict

# Logical sources; each maps to a concrete AWS log stream in the cloud
# instantiation (see docs/architecture.md, Table 2).
SRC_API_AUTH = "api.auth"          # -> Cognito / API Gateway access logs
SRC_API_COMMAND = "api.command"    # -> application logs (CloudWatch Logs)
SRC_GS_UPLINK = "gs.uplink"        # -> ground station modem/front-end logs
SRC_GS_DOWNLINK = "gs.downlink"    # -> ground station frame processor logs
SRC_SAT_TLM = "sat.telemetry"      # -> telemetry stream (Kinesis Data Streams)
SRC_CLOUD_AUDIT = "cloud.audit"    # -> CloudTrail management events
SRC_CLOUD_DATA = "cloud.data"      # -> CloudTrail S3 data events
SRC_IR = "ir.action"               # -> response actions taken by the SOAR layer

OUTCOME_SUCCESS = "success"
OUTCOME_FAILURE = "failure"


@dataclass
class Event:
    """A single normalized observation.

    Args:
        ts: simulated epoch seconds.
        source: one of the ``SRC_*`` constants.
        event_type: dotted verb, e.g. ``auth.login`` or ``command.execute``.
        actor: the principal that caused the event (operator id, IAM role, sat).
        target: the object acted upon (spacecraft id, S3 key, subsystem).
        outcome: ``success`` or ``failure``.
        src_ip: network origin when meaningful.
        attrs: free-form, rule-specific detail.
        ground_truth: ``benign`` or the attack id (``A1``..``A5``). Never visible
            to the detection engine; used only to score the experiment.
    """

    ts: float
    source: str
    event_type: str
    actor: str = "-"
    target: str = "-"
    outcome: str = OUTCOME_SUCCESS
    src_ip: str = "-"
    attrs: Dict[str, Any] = field(default_factory=dict)
    ground_truth: str = "benign"

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, default=str)

    @property
    def is_malicious(self) -> bool:
        return self.ground_truth != "benign"
