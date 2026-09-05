"""Minimal CCSDS-flavoured framing for telecommand and telemetry.

Only the fields the detections actually reason about are modelled: APID
(subsystem), frame sequence counter, payload and the SDLS-style security
trailer. This keeps the testbed readable while preserving the structural
properties that make replay and tampering detectable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional

APID_ADCS = 0x21   # attitude determination and control
APID_EPS = 0x22    # electrical power
APID_PAYLOAD = 0x23
APID_COMMS = 0x24
APID_HOUSEKEEPING = 0x30

APID_NAMES = {
    APID_ADCS: "adcs",
    APID_EPS: "eps",
    APID_PAYLOAD: "payload",
    APID_COMMS: "comms",
    APID_HOUSEKEEPING: "housekeeping",
}


@dataclass
class SpacePacket:
    apid: int
    seq: int
    kind: str                       # "TC" (telecommand) or "TM" (telemetry)
    payload: Dict[str, Any] = field(default_factory=dict)
    tag: Optional[str] = None       # SDLS authentication tag
    emitted_at: float = 0.0         # simulated epoch seconds at emission

    def payload_bytes(self) -> bytes:
        return json.dumps(self.payload, sort_keys=True).encode()

    def subsystem(self) -> str:
        return APID_NAMES.get(self.apid, f"apid_{self.apid:#x}")

    def copy(self) -> "SpacePacket":
        return SpacePacket(**{**asdict(self), "payload": dict(self.payload)})
