"""Testbed assembly and the nominal-operations workload generator.

``build_world`` wires the five layers together (spacecraft, ground station,
mission-control API, cloud archive, SIEM/SOAR) under a single virtual clock.
``NominalOperations`` then drives *benign* mission activity, including the
benign anomalies that a real ground segment produces every day:

* operators fat-finger their passwords,
* an operator occasionally connects from a mobile network or while travelling,
* the RF channel corrupts frames at low elevation,
* a scheduled analytics job bulk-reads the archive once a week.

These are the sources of the false positives measured in RQ2. A testbed without
them would report a false-positive rate of zero and would say nothing useful.
"""

from __future__ import annotations

import heapq
import itertools
import random
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .api.app import MissionControlAPI, Operator
from .blocks import DEFAULT_BLOCK_TTL_S, BlockList
from .bus import EventBus
from .clock import Clock
from .cloud.archive import IamPlane, TelemetryArchive
from .crypto import KeyStore
from .groundstation.station import GroundStation
from .ir.responder import AutomatedResponder
from .satellite.orbit import GroundSite, Orbit
from .satellite.simulator import Spacecraft
from .siem.engine import DetectionConfig, DetectionEngine

SPACECRAFT_ID = "SAT-ALPHA-1"


@dataclass
class Defenses:
    """Preventive controls, individually switchable for the ablation study."""

    sdls_authentication: bool = True   # HMAC tag on every uplinked frame
    anti_replay_window: bool = True    # spacecraft-side sequence window
    rbac: bool = True                  # per-role command allowlist
    mfa: bool = True
    rate_limit: bool = True
    pass_window_check: bool = True
    auto_response: bool = True
    #: How long an automated block holds before it lifts. ``None`` never lifts
    #: it, which is what the ablation contrasts against.
    block_ttl_s: Optional[float] = DEFAULT_BLOCK_TTL_S

    @classmethod
    def none(cls) -> "Defenses":
        return cls(False, False, False, False, False, False, False)


@dataclass
class World:
    clock: Clock
    bus: EventBus
    spacecraft: Spacecraft
    ground_station: GroundStation
    api: MissionControlAPI
    archive: TelemetryArchive
    iam: IamPlane
    engine: DetectionEngine
    responder: AutomatedResponder
    rng: random.Random
    defenses: Defenses
    uplink_quarantined: bool = False
    telemetry_trusted: bool = True
    step_up_required: set = field(default_factory=set)
    _queue: List = field(default_factory=list)
    _counter: itertools.count = field(default_factory=itertools.count)

    # -------------------------------------------------------------- scheduler
    def at(self, t: float, fn: Callable[[float], None]) -> None:
        """Run ``fn(t)`` when the simulation clock reaches ``t``."""
        heapq.heappush(self._queue, (t, next(self._counter), fn))

    def _drain_until(self, t: float) -> None:
        while self._queue and self._queue[0][0] <= t:
            when, _, fn = heapq.heappop(self._queue)
            fn(when)

    @property
    def now(self) -> float:
        return self.clock.now


def build_world(
    seed: int = 1,
    defenses: Optional[Defenses] = None,
    detection: Optional[DetectionConfig] = None,
    archive_path: Optional[str] = None,
) -> World:
    rng = random.Random(seed)
    defenses = defenses or Defenses()
    clock = Clock()
    bus = EventBus(archive_path)

    keys = KeyStore()
    sa = keys.register(SPACECRAFT_ID, bytes(rng.getrandbits(8) for _ in range(32)))
    orbit = Orbit(altitude_m=550_000, inclination_deg=53.0, raan_deg=20.0)
    sc = Spacecraft(
        spacecraft_id=SPACECRAFT_ID, orbit=orbit, sa=sa,
        rng=random.Random(seed + 1),
        require_auth=defenses.sdls_authentication,
        require_anti_replay=defenses.anti_replay_window,
    )
    site = GroundSite(name="GS-SVL", lat_deg=-23.55, lon_deg=-46.63, min_elevation_deg=10.0)
    gs = GroundStation(site=site, spacecraft=sc, bus=bus, rng=random.Random(seed + 2))

    api = MissionControlAPI(
        bus=bus, ground_station=gs, rng=random.Random(seed + 3),
        enforce_rbac=defenses.rbac, enforce_mfa=defenses.mfa,
        enforce_rate_limit=defenses.rate_limit,
        enforce_pass_window=defenses.pass_window_check,
        blocked_principals=BlockList(ttl_s=defenses.block_ttl_s),
    )
    for op in (
        Operator("m.alves", "flight_director", "fd-Pa55!2026", "200.147.35.10"),
        Operator("r.souza", "operator", "op-Sec#2026a", "200.147.35.11"),
        Operator("j.pereira", "operator", "op-Sec#2026b", "200.147.35.12"),
        Operator("l.costa", "observer", "obs-View#26", "200.147.35.13"),
        Operator("svc.analytics", "observer", "svc-9f2b1c77aa", "10.30.4.20",
                 usual_asn="AS16509-AWS", mfa_enrolled=False),
    ):
        api.add_operator(op)

    archive = TelemetryArchive(
        bus=bus, blocked_principals=BlockList(ttl_s=defenses.block_ttl_s))
    iam = IamPlane(bus=bus)
    engine = DetectionEngine(detection or DetectionConfig())

    world = World(
        clock=clock, bus=bus, spacecraft=sc, ground_station=gs, api=api,
        archive=archive, iam=iam, engine=engine,
        responder=AutomatedResponder(world=None, bus=bus),  # patched below
        rng=rng, defenses=defenses,
    )
    world.responder.world = world
    world.responder.enabled = defenses.auto_response

    # SIEM consumes every event; the SOAR layer consumes every alert.
    def _ingest(ev):
        before = len(engine.alerts)
        engine.consume(ev)
        for alert in engine.alerts[before:]:
            world.responder.handle(alert)

    bus.subscribe(_ingest)
    return world


# --------------------------------------------------------------------------
@dataclass
class NominalOperations:
    """Benign mission workload, including realistic benign anomalies."""

    world: World
    tm_period_s: float = 5.0
    dump_objects_per_pass: int = 20
    dump_object_bytes: int = 48 * 1024 * 1024
    analyst_reads_per_hour: int = 6
    typo_probability: float = 0.06
    roaming_probability: float = 0.02
    weekly_bulk_job: bool = True

    _tokens: dict = field(default_factory=dict)
    _last_tm: float = 0.0
    _last_hour: float = -1.0
    _obj_counter: int = 0
    _pass_active: bool = False

    OPERATORS = ("r.souza", "j.pereira", "m.alves", "l.costa")
    ROUTINE_COMMANDS = ("PING", "HK_REQUEST", "TLM_RATE_SET", "PAYLOAD_ON",
                        "PAYLOAD_OFF", "RECORDER_DUMP")
    ROAMING_ORIGINS = (("179.108.4.77", "AS53006-BR"), ("187.19.200.5", "AS28573-BR"))

    # ------------------------------------------------------------------ step
    def step(self, t: float, dt: float) -> None:
        w = self.world
        w.spacecraft.step(t, dt)
        visible = w.ground_station.visible(t)

        if visible and not self._pass_active:
            self._pass_active = True
            self._on_aos(t)
        elif not visible and self._pass_active:
            self._pass_active = False
            self._on_los(t)

        # Telemetry flows whenever there is a link. Quarantine stops the station
        # transmitting, never receiving: cutting your own downlink during an
        # incident destroys the evidence you are about to need.
        if visible and t - self._last_tm >= self.tm_period_s:
            self._last_tm = t
            w.ground_station.receive_tm(w.spacecraft.emit_tm(t), t)

        hour = t // 3600
        if hour != self._last_hour:
            self._last_hour = hour
            self._hourly(t)

    # --------------------------------------------------------------- helpers
    def _login(self, user: str, t: float) -> Optional[str]:
        w = self.world
        op = w.api.operators[user]
        ip, asn = op.usual_ip, op.usual_asn
        if w.rng.random() < self.roaming_probability:
            ip, asn = w.rng.choice(self.ROAMING_ORIGINS)
        # benign failed attempts (typos), occasionally enough to look like a
        # brute-force burst -- this is a deliberate false-positive source
        for _ in range(w.rng.choices([0, 1, 2, 5], weights=[88, 8, 3, 1])[0]):
            w.api.login(user, "wrong-password", ip, t, asn=asn)
            t += 3.0
        token = w.api.login(user, op.password, ip, t, asn=asn)
        if token:
            self._tokens[user] = token
        return token

    def _on_aos(self, t: float) -> None:
        """Acquisition of signal: an operator logs in and runs the pass."""
        w = self.world
        user = w.rng.choice(self.OPERATORS)
        token = self._login(user, t)
        if not token:
            return
        n = w.rng.randint(3, 7)
        for i in range(n):
            cmd = w.rng.choice(self.ROUTINE_COMMANDS)
            if w.api.operators[user].role == "observer":
                cmd = w.rng.choice(("PING", "HK_REQUEST"))
            w.at(t + 20 + i * 25, lambda tt, c=cmd, tk=token: w.api.submit_command(tk, c, tt))
        # the flight director periodically performs a legitimate critical
        # manoeuvre, which is what gives R04 a baseline to learn from
        if w.rng.random() < 0.25:
            fd_token = self._login("m.alves", t + 5)
            if fd_token:
                w.at(t + 120, lambda tt, tk=fd_token: w.api.submit_command(
                    tk, "WHEEL_SPEED_SET", tt, args={"rpm": 1500}))

    def _on_los(self, t: float) -> None:
        """Loss of signal: the pass recorder dump lands in the archive."""
        for _ in range(self.dump_objects_per_pass):
            self._obj_counter += 1
            key = f"raw/{int(t)}/pass-{self._obj_counter:06d}.ccsds"
            self.world.archive.put(key, self.dump_object_bytes)

    def _hourly(self, t: float) -> None:
        w = self.world
        keys = w.archive.keys()
        if not keys:
            return
        for i in range(self.analyst_reads_per_hour):
            key = w.rng.choice(keys[-120:])
            w.at(t + i * 90 + w.rng.random() * 60,
                 lambda tt, k=key: w.archive.get("svc.analytics", k, tt,
                                                 src_ip="10.30.4.20"))
        # a legitimate weekly reprocessing job reads a large slice of the
        # archive: the hardest benign case for the exfiltration detections
        if self.weekly_bulk_job and int(t // 3600) % 168 == 3:
            for i, key in enumerate(keys[-200:]):
                w.at(t + 60 + i * 2,
                     lambda tt, k=key: w.archive.get("svc.reprocessing", k, tt,
                                                     src_ip="10.30.9.44"))


def run_simulation(
    world: World, duration_s: float, ops: Optional[NominalOperations] = None,
    dt: float = 5.0,
) -> NominalOperations:
    """Advance the world by ``duration_s`` simulated seconds."""
    ops = ops or NominalOperations(world)
    end = world.clock.now + duration_s
    while world.clock.now < end:
        t = world.clock.now
        world._drain_until(t)
        ops.step(t, dt)
        world.clock.tick(dt)
    world._drain_until(world.clock.now)
    return ops
