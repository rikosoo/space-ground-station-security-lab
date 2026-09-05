"""Cloud data plane and control plane stand-ins.

:class:`TelemetryArchive` models the S3 bucket that stores downlinked telemetry
products; every read emits a CloudTrail *data* event, which is the only place
attack A5 (data exfiltration) becomes visible. :class:`IamPlane` models the
CloudTrail *management* events an attacker touches when they persist or try to
blind the pipeline (key creation, logging disablement, policy relaxation).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from ..bus import EventBus
from ..events import (
    OUTCOME_FAILURE,
    OUTCOME_SUCCESS,
    SRC_CLOUD_AUDIT,
    SRC_CLOUD_DATA,
    Event,
)


@dataclass
class TelemetryArchive:
    bus: EventBus
    bucket: str = "sgs-telemetry-archive"
    objects: Dict[str, int] = field(default_factory=dict)  # key -> size bytes
    blocked_principals: set = field(default_factory=set)
    reads: List[dict] = field(default_factory=list)

    def put(self, key: str, size_bytes: int) -> None:
        self.objects[key] = size_bytes

    def keys(self) -> List[str]:
        return sorted(self.objects)

    def get(
        self, principal: str, key: str, t: float, src_ip: str = "-",
        ground_truth: str = "benign", user_agent: str = "aws-sdk-python/1.34",
    ) -> int:
        denied = principal in self.blocked_principals
        size = self.objects.get(key, 0)
        if not denied:
            self.reads.append({"t": t, "principal": principal, "key": key, "bytes": size})
        self.bus.publish(
            Event(
                ts=t, source=SRC_CLOUD_DATA, event_type="s3.GetObject",
                actor=principal, target=f"{self.bucket}/{key}",
                outcome=OUTCOME_FAILURE if denied else OUTCOME_SUCCESS, src_ip=src_ip,
                attrs={
                    "bucket": self.bucket, "key": key,
                    "bytes": 0 if denied else size,
                    "user_agent": user_agent,
                    "error_code": "AccessDenied" if denied else "-",
                },
                ground_truth=ground_truth,
            )
        )
        return 0 if denied else size


@dataclass
class IamPlane:
    """CloudTrail management-event surface."""

    bus: EventBus
    logging_enabled: bool = True

    def call(
        self, principal: str, action: str, t: float, src_ip: str = "-",
        ground_truth: str = "benign", **attrs,
    ) -> None:
        if action == "cloudtrail:StopLogging":
            self.logging_enabled = False
        self.bus.publish(
            Event(
                ts=t, source=SRC_CLOUD_AUDIT, event_type=action,
                actor=principal, target=attrs.pop("resource", "-"),
                outcome=OUTCOME_SUCCESS, src_ip=src_ip,
                attrs=attrs, ground_truth=ground_truth,
            )
        )
