"""A2 - Unauthorized telecommand.

Threat model: the adversary, holding the operator session obtained in A1,
escalates from reconnaissance to effect. Three variants are executed in one
scenario because they exercise three different defensive layers:

* **v1 - API abuse**: a critical command (``THRUSTER_FIRE``) is submitted with a
  role that is not entitled to it. The RBAC allowlist should refuse it (R03);
  with RBAC disabled the behavioural rule R04 is the only thing left.
* **v2 - timing abuse**: a command is submitted while the spacecraft is below the
  horizon, i.e. outside any feasible link - a signature of an actor working from
  a script rather than from a pass plan.
* **v3 - RF injection**: the API is bypassed entirely and a forged frame is put
  on the uplink. Only the spacecraft-side SDLS check can stop this one (R05).

This is the scenario where prevention and detection diverge most sharply, and it
is the core of the answer to RQ4.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from spacelab.attacks import Scenario, ScenarioResult  # noqa: E402

# a different operator from A1: containment of one account must not be
# mistaken for containment of the intrusion as a whole
VICTIM = "j.pereira"
ATTACKER_IP = "45.83.12.207"


class UnauthorizedCommand(Scenario):
    id = "A2"
    name = "Unauthorized telecommand against the spacecraft bus"
    objective = "Execute a critical command the compromised role must not issue."
    sparta = "SPARTA EX-0012, EX-0009, IA-0008"
    kill_chain = "stolen session -> privilege abuse -> critical command -> RF injection"
    expected_rules = ("R03", "R04", "R05")

    def plan(self, world, t_start: float) -> ScenarioResult:
        api = world.api
        t0 = self.next_pass(world, t_start, offset_s=60.0)
        res = ScenarioResult(self.id, self.name, t0)

        state = {}

        def _hijack(tt):
            # the operator's second factor was relayed by an AiTM proxy, so the
            # adversary holds a fully authenticated session
            state["token"] = api.hijack_session(
                VICTIM, ATTACKER_IP, tt, asn="AS49505-RU",
                user_agent="python-requests/2.31", ground_truth=self.id)

        world.at(t0, _hijack)
        res.phase(t0, "session_hijack", src_ip=ATTACKER_IP, asn="AS49505-RU")

        # v1: critical command with an unentitled role
        for i, (cmd, args) in enumerate((
            ("SAFE_MODE_ENTER", {}),
            ("THRUSTER_FIRE", {"duration_s": 4.0}),
            ("ATT_SLEW", {"rate_dps": 6.5}),
        )):
            world.at(t0 + 20 + i * 15, lambda tt, c=cmd, a=args: state.get("token") and
                     api.submit_command(state["token"], c, tt, args=a,
                                        src_ip=ATTACKER_IP, ground_truth=self.id))
        res.phase(t0 + 20, "privilege_abuse", variant="v1_api_rbac", commands=3)

        # v2: command with no feasible link
        t_dark = self.outside_pass(world, t0 + 120)
        world.at(t_dark, lambda tt: state.get("token") and api.submit_command(
            state["token"], "THRUSTER_FIRE", tt, args={"duration_s": 9.0},
            src_ip=ATTACKER_IP, ground_truth=self.id))
        res.phase(t_dark, "out_of_window_command", variant="v2_timing")

        # v3: forged frame injected directly on the uplink, bypassing the API
        t_rf = self.next_pass(world, t_dark, offset_s=90.0)
        world.at(t_rf, lambda tt: api.uplink(
            "SAFE_MODE_EXIT", {}, tt, actor="rf-injector", src_ip="-",
            ground_truth=self.id, spoof_tag=True))
        world.at(t_rf + 12, lambda tt: api.uplink(
            "THRUSTER_FIRE", {"duration_s": 12.0}, tt, actor="rf-injector",
            src_ip="-", ground_truth=self.id, spoof_tag=True))
        res.phase(t_rf, "rf_injection", variant="v3_forged_frames", frames=2)
        return res


SCENARIO = UnauthorizedCommand()
