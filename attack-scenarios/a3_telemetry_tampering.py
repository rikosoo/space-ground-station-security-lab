"""A3 - Telemetry tampering.

Threat model: the adversary has a foothold *inside* the ground segment, between
the demodulator and the cloud ingestion point, and wants the operations team to
see a healthy spacecraft while a subsystem degrades - the space-segment analogue
of a process-control false-data-injection attack.

Two phases with very different detectability:

* **Phase 1 - crude injection.** Forged frames carry values that are physically
  impossible (a battery jumping tens of percent between consecutive samples).
  They also fail the SDLS tag check, so cryptographic integrity catches them
  first (R06) and the physics rule (R07) catches them independently.
* **Phase 2 - integrity first.** The adversary first issues ``TLM_AUTH_DISABLE``
  so that frames arrive unauthenticated, then freezes the state of charge at a
  plausible constant. The cryptographic check can no longer help; only the
  control-plane rule that flags the disablement (R11) and the stuck-channel
  branch of the physics rule (R07) remain.

The contrast between the two phases is the paper's main evidence that
cryptographic integrity on the downlink and physics-aware analytics are
complementary, not redundant.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from spacelab.attacks import Scenario, ScenarioResult  # noqa: E402
from spacelab.ccsds import APID_HOUSEKEEPING, SpacePacket  # noqa: E402

ATTACKER = "m.alves"          # compromised flight-director account
ATTACKER_IP = "45.83.12.207"


class TelemetryTampering(Scenario):
    id = "A3"
    name = "False data injection into the telemetry stream"
    objective = "Mask a degrading power subsystem from the operations team."
    sparta = "SPARTA IMP-0002, EXF-0006 / ATT&CK T1565.002"
    kill_chain = "ground-segment foothold -> forged frames -> disable frame auth -> stealth"
    expected_rules = ("R06", "R07", "R11")

    crude_frames = 6
    stealth_frames = 20
    frame_interval_s = 5.0

    def plan(self, world, t_start: float) -> ScenarioResult:
        t0 = self.next_pass(world, t_start, offset_s=60.0)
        res = ScenarioResult(self.id, self.name, t0)
        gs, sc = world.ground_station, world.spacecraft

        def inject(tt, payload_overrides):
            payload = {
                "battery_soc_pct": round(sc.state.battery_soc_pct, 3),
                "battery_voltage_v": round(sc.state.battery_voltage_v, 3),
                "bus_current_a": round(sc.state.bus_current_a, 3),
                "temp_battery_c": round(sc.state.temp_battery_c, 3),
                "temp_payload_c": round(sc.state.temp_payload_c, 3),
                "gyro_x_dps": round(sc.state.gyro_x_dps, 4),
                "gyro_y_dps": round(sc.state.gyro_y_dps, 4),
                "gyro_z_dps": round(sc.state.gyro_z_dps, 4),
                "reaction_wheel_rpm": round(sc.state.reaction_wheel_rpm, 2),
                "payload_on": sc.state.payload_on,
                "safe_mode": sc.state.safe_mode,
                "eclipse": sc.orbit.in_eclipse(tt),
            }
            payload.update(payload_overrides)
            pkt = SpacePacket(apid=APID_HOUSEKEEPING, seq=sc.tm_seq, kind="TM",
                              payload=payload, emitted_at=tt)
            if sc.state.tm_auth_enabled:
                pkt.tag = "de" * 16          # forged tag: the key is not known
            sc.tm_seq += 1
            gs.receive_tm(pkt, tt, ground_truth=self.id, injected=True)

        # ---------------------------------------------------- phase 1: crude
        for i in range(self.crude_frames):
            world.at(t0 + i * self.frame_interval_s,
                     lambda tt, i=i: inject(tt, {
                         "battery_soc_pct": 97.5,
                         "battery_voltage_v": 32.9,
                         "temp_battery_c": 11.0 + 0.1 * i}))
        res.phase(t0, "crude_injection", frames=self.crude_frames,
                  technique="implausible_values_forged_tag")

        # ------------------------------------------- phase 2: disable, freeze
        t_disable = self.next_pass(world, t0 + 3600, offset_s=60.0)
        state = {}

        def _disable(tt):
            token = world.api.hijack_session(
                ATTACKER, ATTACKER_IP, tt, asn="AS49505-RU",
                user_agent="python-requests/2.31", ground_truth=self.id)
            state["token"] = token
            if token:
                world.api.submit_command(token, "TLM_AUTH_DISABLE", tt,
                                         src_ip=ATTACKER_IP, ground_truth=self.id)

        world.at(t_disable, _disable)
        res.phase(t_disable, "disable_frame_authentication", command="TLM_AUTH_DISABLE")

        frozen = {"soc": None}

        def _freeze(tt):
            if frozen["soc"] is None:
                frozen["soc"] = round(sc.state.battery_soc_pct, 3)
            inject(tt, {"battery_soc_pct": frozen["soc"],
                        "battery_voltage_v": 29.9,
                        "temp_battery_c": 12.5,
                        "bus_current_a": 2.4})

        for i in range(self.stealth_frames):
            world.at(t_disable + 60 + i * self.frame_interval_s, _freeze)
        res.phase(t_disable + 60, "stealth_freeze", frames=self.stealth_frames,
                  technique="constant_value_unauthenticated")
        return res


SCENARIO = TelemetryTampering()
