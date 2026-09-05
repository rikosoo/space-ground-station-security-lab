"""A5 - Mission data exfiltration.

Threat model: the adversary has compromised the analytics service principal - a
non-human identity with legitimate read access to the telemetry archive and no
MFA, which is the realistic weak point of a cloud ground segment. They first try
to blind the audit trail, mint a persistent access key, and then bulk-read the
archive from outside the corporate network.

Ordering matters and is deliberate. A clumsy adversary touches the control
plane first (creating a key, stopping the trail) and is caught in seconds by
R11. This scenario models the harder case: the adversary uses the access the
compromised principal already has, exfiltrates first, and only covers its tracks
afterwards. Detection therefore has to come from the data plane:

* R09 fires once the number of distinct objects read crosses a threshold, so its
  latency is set by that threshold and by the adversary's read rate,
* R10 fires only when the hourly volume bucket closes, which is why its latency
  is bounded below by the aggregation window rather than by the pipeline,
* R11 fires last, on the anti-forensics step, and in a real incident would only
  ever confirm what the data-plane rules already said.

The scenario is also the strongest test of the false-positive question, because
a legitimate weekly reprocessing job performs a superficially identical bulk
read in the benign workload.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from spacelab.attacks import Scenario, ScenarioResult  # noqa: E402

PRINCIPAL = "svc.analytics"
ATTACKER_IP = "45.83.12.207"
ATTACKER_UA = "s3-sync/0.9 (linux)"


class DataExfiltration(Scenario):
    id = "A5"
    name = "Bulk exfiltration of archived mission telemetry"
    objective = "Copy the mission's telemetry archive out of the account."
    sparta = "SPARTA EXF-0007, EXF-0008, DE-0002 / ATT&CK T1530, T1562.008"
    kill_chain = "service-principal compromise -> bulk read -> persistence -> anti-forensics"
    expected_rules = ("R09", "R10", "R11")

    objects_to_steal = 260
    read_interval_s = 4.0
    blind_audit_trail = True

    def plan(self, world, t_start: float) -> ScenarioResult:
        t0 = t_start
        res = ScenarioResult(self.id, self.name, t0)
        archive, iam = world.archive, world.iam

        # phase 1 - bulk read with the credentials the principal already holds
        def _bulk(tt):
            keys = archive.keys()[-self.objects_to_steal:]
            for i, key in enumerate(keys):
                world.at(tt + i * self.read_interval_s,
                         lambda t2, k=key: archive.get(
                             PRINCIPAL, k, t2, src_ip=ATTACKER_IP,
                             ground_truth=self.id, user_agent=ATTACKER_UA))

        world.at(t0, _bulk)
        res.phase(t0, "bulk_read", objects=self.objects_to_steal,
                  src_ip=ATTACKER_IP,
                  duration_s=self.objects_to_steal * self.read_interval_s)

        # phase 2 - persistence and anti-forensics, after the data is gone
        t_cover = t0 + self.objects_to_steal * self.read_interval_s + 60.0
        world.at(t_cover, lambda tt: iam.call(
            PRINCIPAL, "iam:CreateAccessKey", tt, src_ip=ATTACKER_IP,
            ground_truth=self.id, resource=f"user/{PRINCIPAL}"))
        res.phase(t_cover, "persistence", action="iam:CreateAccessKey")

        if self.blind_audit_trail:
            world.at(t_cover + 30, lambda tt: iam.call(
                PRINCIPAL, "cloudtrail:StopLogging", tt, src_ip=ATTACKER_IP,
                ground_truth=self.id, resource="trail/sgs-audit"))
            res.phase(t_cover + 30, "anti_forensics", action="cloudtrail:StopLogging")
        return res


SCENARIO = DataExfiltration()
