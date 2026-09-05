"""Circular-orbit propagator and ground-station visibility geometry.

A two-body circular model is sufficient here: the experiment needs realistic
*pass windows* (their duration, cadence and the gaps between them), not
metre-level ephemeris accuracy. Pass geometry matters because two detections
(R04 out-of-window command, R07 replay) depend on when the spacecraft is
actually reachable.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

MU = 3.986004418e14      # Earth gravitational parameter, m^3/s^2
R_EARTH = 6_378_137.0    # equatorial radius, m
OMEGA_EARTH = 7.2921159e-5  # rad/s


@dataclass
class Orbit:
    """Circular orbit defined by altitude, inclination and RAAN."""

    altitude_m: float = 550_000.0
    inclination_deg: float = 53.0
    raan_deg: float = 20.0
    arg_lat0_deg: float = 0.0

    @property
    def radius(self) -> float:
        return R_EARTH + self.altitude_m

    @property
    def period_s(self) -> float:
        return 2 * math.pi * math.sqrt(self.radius**3 / MU)

    def position_eci(self, t: float) -> tuple[float, float, float]:
        """Return the ECI position (m) at simulated epoch second ``t``."""
        n = 2 * math.pi / self.period_s
        u = math.radians(self.arg_lat0_deg) + n * t
        i = math.radians(self.inclination_deg)
        raan = math.radians(self.raan_deg)
        r = self.radius
        # position in the orbital plane, then rotate by inclination and RAAN
        xp, yp = r * math.cos(u), r * math.sin(u)
        x = xp * math.cos(raan) - yp * math.cos(i) * math.sin(raan)
        y = xp * math.sin(raan) + yp * math.cos(i) * math.cos(raan)
        z = yp * math.sin(i)
        return x, y, z

    def in_eclipse(self, t: float) -> bool:
        """Cylindrical shadow test against a fixed sun direction (+X ECI)."""
        x, y, z = self.position_eci(t)
        behind = x < 0
        radial = math.hypot(y, z)
        return behind and radial < R_EARTH


@dataclass
class GroundSite:
    """A ground station antenna site."""

    name: str = "GS-SVL"
    lat_deg: float = -23.55
    lon_deg: float = -46.63
    alt_m: float = 760.0
    min_elevation_deg: float = 10.0

    def position_eci(self, t: float) -> tuple[float, float, float]:
        lat = math.radians(self.lat_deg)
        theta = math.radians(self.lon_deg) + OMEGA_EARTH * t
        r = R_EARTH + self.alt_m
        return (
            r * math.cos(lat) * math.cos(theta),
            r * math.cos(lat) * math.sin(theta),
            r * math.sin(lat),
        )

    def elevation_deg(self, orbit: Orbit, t: float) -> float:
        sx, sy, sz = orbit.position_eci(t)
        gx, gy, gz = self.position_eci(t)
        rx, ry, rz = sx - gx, sy - gy, sz - gz
        rng = math.sqrt(rx * rx + ry * ry + rz * rz)
        gnorm = math.sqrt(gx * gx + gy * gy + gz * gz)
        # angle between the site's zenith (its own position vector) and the
        # site->satellite vector
        cos_zenith = (rx * gx + ry * gy + rz * gz) / (rng * gnorm)
        cos_zenith = max(-1.0, min(1.0, cos_zenith))
        return 90.0 - math.degrees(math.acos(cos_zenith))

    def is_visible(self, orbit: Orbit, t: float) -> bool:
        return self.elevation_deg(orbit, t) >= self.min_elevation_deg

    def next_passes(
        self, orbit: Orbit, t_start: float, horizon_s: float, step_s: float = 10.0
    ) -> list[tuple[float, float]]:
        """Coarse pass search: returns (aos, los) simulated-second pairs."""
        passes: list[tuple[float, float]] = []
        aos: float | None = None
        t = t_start
        while t <= t_start + horizon_s:
            vis = self.is_visible(orbit, t)
            if vis and aos is None:
                aos = t
            elif not vis and aos is not None:
                passes.append((aos, t))
                aos = None
            t += step_s
        if aos is not None:
            passes.append((aos, t_start + horizon_s))
        return passes
