"""Tests for the testbed's load-bearing behaviour.

These are the properties the measurements depend on. If one of them breaks, the
numbers in the paper are wrong rather than merely different, so each test names
the claim it protects.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from spacelab.attacks import load_scenarios  # noqa: E402
from spacelab.ccsds import APID_HOUSEKEEPING, SpacePacket  # noqa: E402
from spacelab.crypto import AntiReplayWindow, sign, verify  # noqa: E402
from spacelab.experiment import TrialConfig, run_trial  # noqa: E402
from spacelab.satellite.orbit import GroundSite, Orbit  # noqa: E402
from spacelab.siem.rules import ALL_RULES  # noqa: E402
from spacelab.world import Defenses, build_world, run_simulation  # noqa: E402


# --------------------------------------------------------------------- crypto
def test_tag_binds_payload_and_sequence():
    """A tag must not transfer to a different payload or a different counter."""
    key = b"k" * 32
    payload = b'{"command": "PING"}'
    tag = sign(key, payload, 7)
    assert verify(key, payload, 7, tag)
    assert not verify(key, payload, 8, tag)
    assert not verify(key, b'{"command": "THRUSTER_FIRE"}', 7, tag)
    assert not verify(b"j" * 32, payload, 7, tag)


def test_anti_replay_window_rejects_repeats_but_tolerates_reordering():
    w = AntiReplayWindow(width=8)
    assert w.check_and_update(10)
    assert not w.check_and_update(10)      # exact replay
    assert w.check_and_update(9)           # reordered, still inside the window
    assert w.check_and_update(11)
    assert not w.check_and_update(1)       # too old


# ---------------------------------------------------------------------- orbit
def test_pass_geometry_is_physically_plausible():
    orbit, site = Orbit(), GroundSite()
    assert 90 * 60 < orbit.period_s < 100 * 60
    passes = site.next_passes(orbit, 0, 86400)
    assert passes, "a 53 deg orbit must be visible from a mid-latitude site"
    for aos, los in passes:
        assert 120 < los - aos < 1200          # minutes, not hours
    assert 0.25 < sum(orbit.in_eclipse(t) for t in range(0, int(orbit.period_s), 10)) \
        / (orbit.period_s / 10) < 0.45


# ------------------------------------------------------------------ spacecraft
def test_spacecraft_rejects_forged_and_replayed_telecommands():
    world = build_world(seed=3)
    sc = world.spacecraft
    good = SpacePacket(apid=APID_HOUSEKEEPING, seq=1, kind="TC",
                       payload={"command": "PING", "args": {}})
    good.tag = sign(sc.sa.key, good.payload_bytes(), good.seq)
    assert sc.receive_tc(good, 0.0)["accepted"]

    replay = good.copy()
    assert sc.receive_tc(replay, 10.0)["reason"] == "replay_window_reject"

    forged = SpacePacket(apid=APID_HOUSEKEEPING, seq=2, kind="TC",
                         payload={"command": "THRUSTER_FIRE", "args": {}}, tag="00" * 16)
    assert sc.receive_tc(forged, 20.0)["reason"] == "auth_tag_invalid"


def test_power_model_stays_inside_its_envelope():
    """A drifting power model would make the physics rule fire on nothing."""
    world = build_world(seed=5)
    run_simulation(world, 5 * 86400)
    soc = [e.attrs["battery_soc_pct"] for e in world.bus.log
           if e.event_type == "telemetry.sample"]
    assert soc, "no telemetry was produced"
    assert 5.0 < min(soc) and max(soc) < 100.0
    assert max(soc) - min(soc) > 5.0, "state of charge must actually cycle"


# ------------------------------------------------------------------ detections
def test_every_rule_has_a_sigma_file_and_vice_versa():
    """The portable and executable rule packs must not drift apart."""
    ids = {r.id for r in ALL_RULES}
    sigma = {p.name.split("_")[0].upper()
             for p in (ROOT / "detection-rules" / "sigma").glob("*.yml")}
    assert ids == sigma, f"python only: {ids - sigma}, sigma only: {sigma - ids}"


def test_rule_ids_and_tiers_are_well_formed():
    seen = set()
    for rule in ALL_RULES:
        assert rule.id not in seen, f"duplicate rule id {rule.id}"
        seen.add(rule.id)
        assert rule.tier in {"stream", "batch"}
        assert rule.severity in {"low", "medium", "high", "critical"}
        assert rule.technique != "-", f"{rule.id} has no technique mapping"


def test_benign_workload_is_not_alert_free_but_is_quiet():
    """The false-positive measurement is only meaningful if noise exists."""
    world = build_world(seed=11)
    run_simulation(world, 7 * 86400)
    frames = [e for e in world.bus.log if e.event_type == "downlink.frame"]
    corrupted = [e for e in frames if e.attrs.get("channel_corrupted")]
    assert corrupted, "the RF channel never corrupted a frame in a week"
    assert len(corrupted) / len(frames) < 0.02, "link is implausibly bad"


# --------------------------------------------------------------------- attacks
def test_all_five_scenarios_load_and_declare_their_mapping():
    scenarios = load_scenarios()
    assert set(scenarios) == {"A1", "A2", "A3", "A4", "A5"}
    for s in scenarios.values():
        assert s.expected_rules, f"{s.id} declares no expected detections"
        assert s.sparta != "-"


@pytest.mark.parametrize("attack_id", ["A1", "A2", "A3", "A4", "A5"])
def test_each_attack_is_detected_end_to_end(attack_id):
    result = run_trial(TrialConfig(seed=42, warmup_days=5, measure_days=3,
                                   scenario_ids=[attack_id]))
    outcome = result.outcomes[attack_id]
    assert outcome.detected, f"{attack_id} went undetected"
    assert outcome.ttd_s is not None and outcome.ttd_s >= 0
    expected = set(load_scenarios()[attack_id].expected_rules)
    assert set(outcome.all_rules) & expected, (
        f"{attack_id} fired {outcome.all_rules}, expected any of {sorted(expected)}")


def test_ground_truth_never_reaches_the_detection_engine():
    """Scoring would be circular if a rule could read the label."""
    import inspect

    from spacelab.siem import rules as rules_module

    source = inspect.getsource(rules_module)
    assert "ground_truth" not in source, "a rule inspects the ground-truth label"


# -------------------------------------------------------------------- ablation
def test_disabling_anti_replay_lets_the_replay_execute():
    """The ablation must actually change the outcome it claims to change."""
    protected = run_trial(TrialConfig(seed=7, warmup_days=5, measure_days=4,
                                      scenario_ids=["A4"]))
    exposed = run_trial(TrialConfig(
        seed=7, warmup_days=5, measure_days=4, scenario_ids=["A4"],
        defenses=Defenses(anti_replay_window=False, auto_response=False)))
    assert protected.outcomes["A4"].malicious_successes == 0
    assert exposed.outcomes["A4"].malicious_successes > 0
    assert exposed.outcomes["A4"].detected, "ground-side duplicate detection must remain"


def test_archive_volume_rule_reports_a_burst_that_containment_silenced():
    """R10 must close its window on the clock, not on the principal's next read.

    Once R09 fires and the responder denies the principal, no further read
    arrives. A rule that waits for one never evaluates the hour the burst
    happened in, and so can never report the exfiltration it exists to detect.
    """
    result = run_trial(TrialConfig(seed=1000, warmup_days=7, measure_days=7,
                                   scenario_ids=["A5"]))
    outcome = result.outcomes["A5"]
    assert outcome.contained, "the scenario under test is the contained one"
    assert "R10" in outcome.all_rules, "R10 never evaluated the burst's hour"


def test_determinism():
    """Same seed, same numbers - the reproducibility claim in the paper."""
    a = run_trial(TrialConfig(seed=99, warmup_days=4, measure_days=3))
    b = run_trial(TrialConfig(seed=99, warmup_days=4, measure_days=3))
    assert [o.ttd_s for o in a.outcomes.values()] == [o.ttd_s for o in b.outcomes.values()]
    assert a.false_positives == b.false_positives


# ----------------------------------------------------------------------- paper
def test_paper_macros_are_all_defined():
    """Every generated macro the paper uses must exist, or the PDF shows '??'."""
    import re

    generated = ROOT / "research" / "paper" / "generated" / "results.tex"
    if not generated.exists():
        pytest.skip("run `python research/experiments/make_macros.py` first")
    defined = set(re.findall(r"\\newcommand\{\\(\w+)\}", generated.read_text()))
    used = set()
    for path in (ROOT / "research" / "paper" / "sections").glob("*.tex"):
        used |= set(re.findall(r"\\(Res\w+|Abl\w+|Sweep\w+|Cost\w+)", path.read_text()))
    assert used <= defined, f"undefined in the paper: {sorted(used - defined)}"


def test_paper_includes_every_generated_table():
    """A generated table nobody inputs is a table that silently went stale."""
    out = ROOT / "research" / "paper" / "generated"
    if not out.exists():
        pytest.skip("run `python research/experiments/make_macros.py` first")
    body = "".join(p.read_text() for p in
                   (ROOT / "research" / "paper" / "sections").glob("*.tex"))
    for table in out.glob("tab-*.tex"):
        stem = table.stem
        if stem in {"tab-sweep-exfil-key-threshold", "tab-sweep-dedup-cooldown-s"}:
            continue  # swept for the repository results, not shown in the paper
        assert f"generated/{stem}" in body, f"{stem} is generated but never included"
