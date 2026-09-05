"""Link-layer authentication primitives for the TT&C path.

Models the two controls that CCSDS SDLS (CCSDS 355.0-B) provides in practice:

* an authentication tag over the frame (here HMAC-SHA256, truncated to 16 bytes),
* a monotonically increasing anti-replay sequence number per security association.

Both can be independently disabled by the experiment harness so that each
control's contribution to prevention and detection can be measured (RQ4).
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Dict

TAG_LEN = 16


def sign(key: bytes, payload: bytes, seq: int) -> str:
    """Return the truncated HMAC tag binding ``payload`` to ``seq``."""
    mac = hmac.new(key, seq.to_bytes(8, "big") + payload, hashlib.sha256)
    return mac.hexdigest()[: TAG_LEN * 2]


def verify(key: bytes, payload: bytes, seq: int, tag: str) -> bool:
    return hmac.compare_digest(sign(key, payload, seq), tag)


@dataclass
class AntiReplayWindow:
    """Sliding sequence-number window per security association.

    A frame is accepted only if its sequence number is greater than the highest
    one already accepted, or within ``width`` below it and not yet seen. This
    tolerates the frame reordering a real RF link produces while still rejecting
    replays.
    """

    width: int = 64
    highest: int = -1
    seen: set = field(default_factory=set)

    def check_and_update(self, seq: int) -> bool:
        if seq <= self.highest - self.width:
            return False  # too old
        if seq in self.seen:
            return False  # replay
        self.seen.add(seq)
        self.highest = max(self.highest, seq)
        self.seen = {s for s in self.seen if s > self.highest - self.width}
        return True


@dataclass
class SecurityAssociation:
    spacecraft_id: str
    key: bytes
    window: AntiReplayWindow = field(default_factory=AntiReplayWindow)


class KeyStore:
    """Holds per-spacecraft keys. Stands in for AWS KMS + Secrets Manager."""

    def __init__(self) -> None:
        self._sas: Dict[str, SecurityAssociation] = {}

    def register(self, spacecraft_id: str, key: bytes) -> SecurityAssociation:
        sa = SecurityAssociation(spacecraft_id, key)
        self._sas[spacecraft_id] = sa
        return sa

    def get(self, spacecraft_id: str) -> SecurityAssociation:
        return self._sas[spacecraft_id]
