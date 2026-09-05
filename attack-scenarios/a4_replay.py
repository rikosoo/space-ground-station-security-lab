"""A4 - Telecommand replay.

Threat model: the adversary cannot forge an authentication tag, but they do not
need to. With a software-defined radio they record a genuine, correctly
authenticated telecommand during one pass and re-transmit it on a later pass.
The frame is cryptographically perfect; only its freshness is wrong.

The scenario replays a real captured frame twice: once during the very next
pass, and once several passes later, to show that detection latency depends on
when the spacecraft is next reachable rather than on the analytics tier.

Defence in depth is the point here. The spacecraft's anti-replay sequence window
*prevents* execution and produces a rejection event (R08). If the window is
disabled in the ablation, the command executes and the only remaining signal is
the ground-side duplicate frame-counter observation - same rule, different
evidence, far worse outcome.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from spacelab.attacks import Scenario, ScenarioResult  # noqa: E402


class ReplayAttack(Scenario):
    id = "A4"
    name = "Replay of a captured authenticated telecommand"
    objective = "Re-execute a valid command without ever holding the key."
    sparta = "SPARTA EX-0013, IA-0008 / ATT&CK T1499"
    kill_chain = "RF capture -> store -> re-transmit on a later pass"
    expected_rules = ("R08",)

    def plan(self, world, t_start: float) -> ScenarioResult:
        gs = world.ground_station
        t0 = self.next_pass(world, t_start, offset_s=120.0)
        res = ScenarioResult(self.id, self.name, t0)
        captured = {}

        def _capture(tt):
            if gs.transmitted:
                captured["pkt"] = gs.transmitted[-1].copy()
                res.phase(tt, "rf_capture",
                          command=captured["pkt"].payload.get("command"),
                          seq=captured["pkt"].seq)

        world.at(t0, _capture)

        def _replay(tt):
            pkt = captured.get("pkt")
            if pkt is None:
                return
            gs.transmit(pkt.copy(), tt, actor="rf-replayer", src_ip="-",
                        ground_truth=self.id)

        t_r1 = self.next_pass(world, t0 + 600, offset_s=100.0)
        world.at(t_r1, _replay)
        res.phase(t_r1, "replay_next_pass")
        # RF capture is passive and leaves no observable in the ground segment,
        # so latency is measured from the first re-transmission.
        res.t0 = t_r1

        t_r2 = self.next_pass(world, t_r1 + 4 * 3600, offset_s=100.0)
        world.at(t_r2, _replay)
        world.at(t_r2 + 20, _replay)
        res.phase(t_r2, "replay_later_pass", frames=2)
        res.notes["t_first_replay"] = t_r1
        return res


SCENARIO = ReplayAttack()
