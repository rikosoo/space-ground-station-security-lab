"""Ground station: RF front-end, frame processing and the cloud uplink.

Responsibilities modelled here:

1. **Link availability** - a telecommand can only reach the vehicle while the
   spacecraft is above the site's mask angle. Attempts outside a pass are the
   observable that feeds detection R04.
2. **Link noise** - a physical channel corrupts frames. Corrupted frames raise
   the same ``integrity_error`` signal that a tampering attack does, which is
   the dominant source of benign noise in this testbed and therefore the main
   driver of the false-positive rate (RQ2).
3. **Normalization** - every RF-side observation is turned into a
   :class:`~spacelab.events.Event` and published on the bus.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import List, Optional

from ..bus import EventBus
from ..ccsds import SpacePacket
from ..crypto import verify
from ..events import (
    OUTCOME_FAILURE,
    OUTCOME_SUCCESS,
    SRC_GS_DOWNLINK,
    SRC_GS_UPLINK,
    SRC_SAT_TLM,
    Event,
)
from ..satellite.orbit import GroundSite
from ..satellite.simulator import Spacecraft


@dataclass
class GroundStation:
    """One antenna site bound to one spacecraft."""

    site: GroundSite
    spacecraft: Spacecraft
    bus: EventBus
    rng: random.Random = field(default_factory=lambda: random.Random(11))
    #: probability that a *received* frame is corrupted at 90 deg elevation.
    base_frame_error_rate: float = 1.0e-3
    downlinked: int = 0
    #: last telecommand frames put on the air, i.e. what an adversary with an
    #: RF receiver could capture and later replay (attack A4).
    transmitted: List[SpacePacket] = field(default_factory=list)

    # ------------------------------------------------------------------ link
    def elevation(self, t: float) -> float:
        return self.site.elevation_deg(self.spacecraft.orbit, t)

    def visible(self, t: float) -> bool:
        return self.site.is_visible(self.spacecraft.orbit, t)

    def frame_error_prob(self, t: float) -> float:
        """Frame error probability grows sharply at low elevation."""
        el = max(self.elevation(t), self.site.min_elevation_deg)
        return self.base_frame_error_rate * math.exp((30.0 - min(el, 60.0)) / 8.0)

    # ---------------------------------------------------------------- uplink
    def transmit(
        self, packet: SpacePacket, t: float, actor: str, src_ip: str, ground_truth: str
    ) -> dict:
        """Transmit a telecommand and publish the resulting uplink event."""
        el = self.elevation(t)
        if not self.visible(t):
            self.bus.publish(
                Event(
                    ts=t, source=SRC_GS_UPLINK, event_type="uplink.transmit",
                    actor=actor, target=self.spacecraft.spacecraft_id,
                    outcome=OUTCOME_FAILURE, src_ip=src_ip,
                    attrs={
                        "command": packet.payload.get("command"),
                        "reason": "no_link_spacecraft_not_visible",
                        "elevation_deg": round(el, 2),
                        "in_pass": False,
                        "site": self.site.name,
                        "seq": packet.seq,
                    },
                    ground_truth=ground_truth,
                )
            )
            return {"accepted": False, "reason": "no_link"}

        self.transmitted.append(packet.copy())
        if len(self.transmitted) > 500:
            del self.transmitted[:100]
        verdict = self.spacecraft.receive_tc(packet, t)
        self.bus.publish(
            Event(
                ts=t, source=SRC_GS_UPLINK, event_type="uplink.transmit",
                actor=actor, target=self.spacecraft.spacecraft_id,
                outcome=OUTCOME_SUCCESS if verdict["accepted"] else OUTCOME_FAILURE,
                src_ip=src_ip,
                attrs={
                    "command": verdict["command"],
                    "reason": verdict["reason"],
                    "elevation_deg": round(el, 2),
                    "in_pass": True,
                    "site": self.site.name,
                    "seq": packet.seq,
                },
                ground_truth=ground_truth,
            )
        )
        return verdict

    # -------------------------------------------------------------- downlink
    def receive_tm(
        self, packet: SpacePacket, t: float, ground_truth: str = "benign",
        injected: bool = False,
    ) -> Optional[SpacePacket]:
        """Demodulate, integrity-check and forward one telemetry frame."""
        corrupted = self.rng.random() < self.frame_error_prob(t)
        pkt = packet
        if corrupted:
            pkt = packet.copy()
            # a bit flip in the payload: value stays in range, tag no longer matches
            pkt.payload["bus_current_a"] = round(
                pkt.payload.get("bus_current_a", 1.0) + self.rng.uniform(-3, 3), 3
            )

        if pkt.tag is None:
            # Frame authentication is switched off on the link: the station has
            # no way to tell a genuine frame from an injected one. This is the
            # state attack A3 tries to reach before it starts tampering.
            tag_ok, integrity = True, "not_verified"
        else:
            tag_ok = verify(self.spacecraft.sa.key, pkt.payload_bytes(), pkt.seq, pkt.tag)
            integrity = "ok" if tag_ok else "auth_tag_mismatch"
        self.downlinked += 1

        self.bus.publish(
            Event(
                ts=t, source=SRC_GS_DOWNLINK, event_type="downlink.frame",
                actor=self.spacecraft.spacecraft_id, target=self.site.name,
                outcome=OUTCOME_SUCCESS if tag_ok else OUTCOME_FAILURE,
                attrs={
                    "seq": pkt.seq,
                    "apid": pkt.apid,
                    "subsystem": pkt.subsystem(),
                    "integrity": integrity,
                    "authenticated": pkt.tag is not None,
                    "channel_corrupted": corrupted,
                    "elevation_deg": round(self.elevation(t), 2),
                    "injected": injected,
                    "emitted_at": pkt.emitted_at,
                    "latency_s": round(t - pkt.emitted_at, 3),
                },
                ground_truth=ground_truth,
            )
        )
        self.bus.publish(
            Event(
                ts=t, source=SRC_SAT_TLM, event_type="telemetry.sample",
                actor=self.spacecraft.spacecraft_id, target="tlm-archive",
                outcome=OUTCOME_SUCCESS,
                attrs={"seq": pkt.seq, "integrity_ok": tag_ok, "authenticated": pkt.tag is not None, **pkt.payload},
                ground_truth=ground_truth,
            )
        )
        return pkt
