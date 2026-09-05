"""Spacecraft bus simulator: subsystem dynamics, telecommand execution, telemetry.

The spacecraft is the last line of defence in the TT&C chain. It verifies the
SDLS authentication tag and the anti-replay sequence window before executing a
telecommand, and it emits housekeeping telemetry whose values follow physical
models. Those models are what make telemetry *tampering* (attack A3) detectable:
a forged value can be made to look plausible in isolation but not consistent
with the rate limits of the underlying physics.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Dict, List

from ..ccsds import (
    APID_ADCS,
    APID_COMMS,
    APID_EPS,
    APID_HOUSEKEEPING,
    APID_PAYLOAD,
    SpacePacket,
)
from ..crypto import SecurityAssociation, verify
from .orbit import Orbit

#: Telecommand catalogue. ``critical`` commands can place the vehicle at risk
#: and are the ones an attacker wants (SPARTA IEX-0001 / EXF-0003 targets).
COMMAND_CATALOG: Dict[str, dict] = {
    "PING": {"apid": APID_COMMS, "critical": False},
    "TLM_RATE_SET": {"apid": APID_COMMS, "critical": False},
    "HK_REQUEST": {"apid": APID_HOUSEKEEPING, "critical": False},
    "PAYLOAD_ON": {"apid": APID_PAYLOAD, "critical": False},
    "PAYLOAD_OFF": {"apid": APID_PAYLOAD, "critical": False},
    "RECORDER_DUMP": {"apid": APID_PAYLOAD, "critical": False},
    "WHEEL_SPEED_SET": {"apid": APID_ADCS, "critical": True},
    "ATT_SLEW": {"apid": APID_ADCS, "critical": True},
    "THRUSTER_FIRE": {"apid": APID_ADCS, "critical": True},
    "SAFE_MODE_ENTER": {"apid": APID_EPS, "critical": True},
    "SAFE_MODE_EXIT": {"apid": APID_EPS, "critical": True},
    "TLM_AUTH_DISABLE": {"apid": APID_COMMS, "critical": True},
    "KEY_ROTATE": {"apid": APID_COMMS, "critical": True},
}

#: Physical envelopes used by the spacecraft FDIR and, independently, by the
#: SIEM's physics-consistency rule (R06). Values are (min, max, max |rate|/s).
TELEMETRY_ENVELOPE = {
    "battery_soc_pct": (0.0, 100.0, 0.05),
    "battery_voltage_v": (22.0, 33.6, 0.05),
    "bus_current_a": (0.0, 12.0, 0.8),
    "temp_battery_c": (-20.0, 45.0, 0.08),
    "temp_payload_c": (-40.0, 60.0, 0.20),
    "gyro_x_dps": (-8.0, 8.0, 0.5),
    "gyro_y_dps": (-8.0, 8.0, 0.5),
    "gyro_z_dps": (-8.0, 8.0, 0.5),
    "reaction_wheel_rpm": (-6000.0, 6000.0, 60.0),
}


@dataclass
class SpacecraftState:
    battery_soc_pct: float = 87.0
    battery_voltage_v: float = 29.4
    bus_current_a: float = 3.1
    temp_battery_c: float = 12.0
    temp_payload_c: float = -5.0
    gyro_x_dps: float = 0.02
    gyro_y_dps: float = -0.01
    gyro_z_dps: float = 0.03
    reaction_wheel_rpm: float = 1200.0
    payload_on: bool = False
    safe_mode: bool = False
    tm_auth_enabled: bool = True


@dataclass
class Spacecraft:
    """A single spacecraft with an orbit, a security association and dynamics."""

    spacecraft_id: str
    orbit: Orbit
    sa: SecurityAssociation
    rng: random.Random = field(default_factory=lambda: random.Random(7))
    state: SpacecraftState = field(default_factory=SpacecraftState)
    tm_seq: int = 0
    require_auth: bool = True
    require_anti_replay: bool = True
    rejected: List[dict] = field(default_factory=list)
    executed: List[dict] = field(default_factory=list)

    # ---------------------------------------------------------------- uplink
    def receive_tc(self, packet: SpacePacket, t: float) -> dict:
        """Validate and (if valid) execute a telecommand.

        Returns a verdict dict with ``accepted`` and a ``reason`` code. The
        reason codes are what the ground segment forwards to the SIEM, so they
        are part of the detection surface.
        """
        name = packet.payload.get("command", "?")

        if self.require_auth:
            ok = packet.tag is not None and verify(
                self.sa.key, packet.payload_bytes(), packet.seq, packet.tag
            )
            if not ok:
                verdict = {"accepted": False, "reason": "auth_tag_invalid", "command": name}
                self.rejected.append(verdict)
                return verdict

        if self.require_anti_replay and not self.sa.window.check_and_update(packet.seq):
            verdict = {"accepted": False, "reason": "replay_window_reject", "command": name}
            self.rejected.append(verdict)
            return verdict

        if name not in COMMAND_CATALOG:
            verdict = {"accepted": False, "reason": "unknown_command", "command": name}
            self.rejected.append(verdict)
            return verdict

        self._apply(name, packet.payload.get("args", {}))
        verdict = {"accepted": True, "reason": "executed", "command": name}
        self.executed.append({"t": t, **verdict})
        return verdict

    def _apply(self, name: str, args: dict) -> None:
        st = self.state
        if name == "PAYLOAD_ON":
            st.payload_on = True
        elif name == "PAYLOAD_OFF":
            st.payload_on = False
        elif name == "SAFE_MODE_ENTER":
            st.safe_mode, st.payload_on = True, False
        elif name == "SAFE_MODE_EXIT":
            st.safe_mode = False
        elif name == "TLM_AUTH_DISABLE":
            st.tm_auth_enabled = False
        elif name == "WHEEL_SPEED_SET":
            st.reaction_wheel_rpm = float(args.get("rpm", st.reaction_wheel_rpm))
        elif name == "ATT_SLEW":
            rate = float(args.get("rate_dps", 1.0))
            st.gyro_z_dps = max(-8.0, min(8.0, rate))
        elif name == "THRUSTER_FIRE":
            st.gyro_x_dps = max(-8.0, min(8.0, st.gyro_x_dps + 1.5))

    # -------------------------------------------------------------- dynamics
    def step(self, t: float, dt: float) -> None:
        """Advance the subsystem models by ``dt`` simulated seconds."""
        st = self.state
        eclipse = self.orbit.in_eclipse(t)
        load = 1.2 + (1.9 if st.payload_on else 0.0) + (0.0 if st.safe_mode else 0.5)
        # Solar array output tapers as the battery approaches full charge
        # (constant-current / constant-voltage behaviour), which keeps the state
        # of charge off its rail and therefore observable.
        taper = max(0.0, 1.0 - (st.battery_soc_pct / 100.0) ** 6)
        charge = 0.0 if eclipse else 5.5 * taper
        d_soc = (charge - load) * dt / 1200.0
        st.battery_soc_pct = max(5.0, min(100.0, st.battery_soc_pct + d_soc))
        st.battery_voltage_v = 22.5 + 0.105 * st.battery_soc_pct + self.rng.gauss(0, 0.01)
        st.bus_current_a = max(0.05, load + self.rng.gauss(0, 0.03))
        target_batt = -4.0 if eclipse else 18.0
        st.temp_battery_c += (target_batt - st.temp_battery_c) * min(1.0, dt / 1800.0)
        target_pl = (25.0 if st.payload_on else -12.0) + (-8.0 if eclipse else 6.0)
        st.temp_payload_c += (target_pl - st.temp_payload_c) * min(1.0, dt / 900.0)
        for axis in ("gyro_x_dps", "gyro_y_dps", "gyro_z_dps"):
            v = getattr(st, axis)
            setattr(st, axis, v * math.exp(-dt / 600.0) + self.rng.gauss(0, 0.004))
        st.reaction_wheel_rpm += self.rng.gauss(0, 1.2) * min(dt, 10.0)
        st.reaction_wheel_rpm = max(-6000.0, min(6000.0, st.reaction_wheel_rpm))

    # -------------------------------------------------------------- downlink
    def emit_tm(self, t: float) -> SpacePacket:
        """Produce an authenticated housekeeping telemetry packet."""
        st = self.state
        payload = {
            "battery_soc_pct": round(st.battery_soc_pct, 3),
            "battery_voltage_v": round(st.battery_voltage_v, 3),
            "bus_current_a": round(st.bus_current_a, 3),
            "temp_battery_c": round(st.temp_battery_c, 3),
            "temp_payload_c": round(st.temp_payload_c, 3),
            "gyro_x_dps": round(st.gyro_x_dps, 4),
            "gyro_y_dps": round(st.gyro_y_dps, 4),
            "gyro_z_dps": round(st.gyro_z_dps, 4),
            "reaction_wheel_rpm": round(st.reaction_wheel_rpm, 2),
            "payload_on": st.payload_on,
            "safe_mode": st.safe_mode,
            "eclipse": self.orbit.in_eclipse(t),
        }
        pkt = SpacePacket(
            apid=APID_HOUSEKEEPING, seq=self.tm_seq, kind="TM",
            payload=payload, emitted_at=t,
        )
        if st.tm_auth_enabled:
            from ..crypto import sign
            pkt.tag = sign(self.sa.key, pkt.payload_bytes(), pkt.seq)
        self.tm_seq += 1
        return pkt
