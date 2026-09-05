"""Loader and shared base class for the controlled attack scenarios.

The scenarios themselves live in ``attack-scenarios/`` so that the repository
layout mirrors the paper's structure. Because that directory name is not a valid
Python identifier, scenarios are loaded by path rather than imported.

Every scenario is *controlled*: it runs entirely inside the testbed, it declares
its own ground-truth label so that scoring is unambiguous, and it records the
simulated time of its first malicious action (``t0``) which is the reference
point for every latency measurement in the paper.
"""

from __future__ import annotations

import importlib.util
import pathlib
from dataclasses import dataclass, field
from typing import Dict, List

SCENARIO_DIR = pathlib.Path(__file__).resolve().parents[2] / "attack-scenarios"


@dataclass
class ScenarioResult:
    attack_id: str
    name: str
    t0: float
    phases: List[dict] = field(default_factory=list)
    notes: Dict = field(default_factory=dict)

    def phase(self, t: float, label: str, **detail) -> None:
        self.phases.append({"t": t, "label": label, **detail})


class Scenario:
    """Base class for a controlled attack."""

    id: str = "A0"
    name: str = "base"
    objective: str = ""
    sparta: str = "-"
    kill_chain: str = ""
    expected_rules: tuple = ()

    def plan(self, world, t_start: float) -> ScenarioResult:
        raise NotImplementedError

    # -- helpers shared by scenarios -------------------------------------
    @staticmethod
    def next_pass(world, t: float, offset_s: float = 30.0) -> float:
        """Simulated time shortly after the next acquisition of signal."""
        passes = world.ground_station.site.next_passes(
            world.spacecraft.orbit, t, 3 * 86400, step_s=10.0
        )
        for aos, los in passes:
            if aos >= t and (los - aos) > 2 * offset_s:
                return aos + offset_s
        return t + 3600.0

    @staticmethod
    def outside_pass(world, t: float) -> float:
        """Simulated time when the spacecraft is *not* reachable."""
        passes = world.ground_station.site.next_passes(
            world.spacecraft.orbit, t, 3 * 86400, step_s=10.0
        )
        for aos, los in passes:
            if los > t:
                return los + 600.0
        return t + 1800.0


def load_scenarios(directory: pathlib.Path | None = None) -> Dict[str, Scenario]:
    """Import every ``a*.py`` scenario module and instantiate its ``SCENARIO``."""
    directory = directory or SCENARIO_DIR
    found: Dict[str, Scenario] = {}
    for path in sorted(directory.glob("a[1-9]_*.py")):
        spec = importlib.util.spec_from_file_location(f"scenario_{path.stem}", path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        scenario = getattr(module, "SCENARIO")
        found[scenario.id] = scenario
    return found
