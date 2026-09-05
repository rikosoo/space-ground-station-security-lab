"""A1 - Credential compromise.

Threat model: the adversary has obtained (phishing, credential stuffing, a leaked
CI secret) a *partial* set of credentials for a mission operator and completes
the attack with password spraying from infrastructure outside the operator's
normal network. They then establish a session and perform reconnaissance with
commands the stolen role is genuinely allowed to issue - the hardest case,
because nothing the session does is by itself illegal.

What should catch it: the burst of failed authentications followed by a success
(R01) and the unprofiled network origin of that success (R02). Note that no
preventive control stops this attack once the password is known; MFA is the only
mechanism in the testbed that does, which is exactly what the ablation measures.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from spacelab.attacks import Scenario, ScenarioResult  # noqa: E402

VICTIM = "r.souza"
ATTACKER_IP = "45.83.12.207"
ATTACKER_ASN = "AS49505-RU"
ATTACKER_UA = "python-requests/2.31"


class CredentialCompromise(Scenario):
    id = "A1"
    name = "Credential compromise of a mission operator account"
    objective = "Obtain an authenticated session on the mission-control API."
    sparta = "SPARTA REC-0005, IA-0004 / ATT&CK T1110.003, T1078"
    kill_chain = "spray -> valid session -> low-privilege reconnaissance"
    expected_rules = ("R01", "R02")

    n_spray_attempts = 9
    spray_interval_s = 11.0

    def plan(self, world, t_start: float) -> ScenarioResult:
        t0 = self.next_pass(world, t_start, offset_s=45.0)
        res = ScenarioResult(self.id, self.name, t0)
        api = world.api
        victim_password = api.operators[VICTIM].password

        for i in range(self.n_spray_attempts):
            t = t0 + i * self.spray_interval_s
            world.at(t, lambda tt, i=i: api.login(
                VICTIM, f"Summer2026!{i}", ATTACKER_IP, tt, asn=ATTACKER_ASN,
                user_agent=ATTACKER_UA, ground_truth=self.id))
        res.phase(t0, "password_spray", attempts=self.n_spray_attempts, src_ip=ATTACKER_IP)

        t_success = t0 + self.n_spray_attempts * self.spray_interval_s
        state = {}

        def _succeed(tt):
            state["token"] = api.login(
                VICTIM, victim_password, ATTACKER_IP, tt, asn=ATTACKER_ASN,
                user_agent=ATTACKER_UA, mfa_presented=False, ground_truth=self.id)

        world.at(t_success, _succeed)
        res.phase(t_success, "session_established", src_ip=ATTACKER_IP, asn=ATTACKER_ASN)

        # in-scope reconnaissance with the stolen role
        for i, cmd in enumerate(("PING", "HK_REQUEST", "HK_REQUEST")):
            world.at(t_success + 30 + i * 20, lambda tt, c=cmd: state.get("token") and
                     api.submit_command(state["token"], c, tt, src_ip=ATTACKER_IP,
                                        ground_truth=self.id))
        res.phase(t_success + 30, "reconnaissance", commands=3)
        res.notes["handoff_token"] = state  # consumed by A2
        return res


SCENARIO = CredentialCompromise()
