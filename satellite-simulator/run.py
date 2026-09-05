#!/usr/bin/env python3
"""Standalone spacecraft simulation: pass geometry and housekeeping telemetry."""

from __future__ import annotations

import argparse
import pathlib
import random
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from spacelab.crypto import KeyStore  # noqa: E402
from spacelab.satellite import GroundSite, Orbit, Spacecraft  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--days", type=float, default=1.0)
    ap.add_argument("--altitude-km", type=float, default=550.0)
    ap.add_argument("--inclination", type=float, default=53.0)
    ap.add_argument("--lat", type=float, default=-23.55)
    ap.add_argument("--lon", type=float, default=-46.63)
    ap.add_argument("--step", type=float, default=5.0)
    args = ap.parse_args()

    orbit = Orbit(altitude_m=args.altitude_km * 1000, inclination_deg=args.inclination)
    site = GroundSite(lat_deg=args.lat, lon_deg=args.lon)
    keys = KeyStore()
    sc = Spacecraft("SAT-ALPHA-1", orbit, keys.register("SAT-ALPHA-1", b"\x00" * 32),
                    rng=random.Random(7))

    horizon = args.days * 86400
    passes = site.next_passes(orbit, 0, horizon)
    print(f"orbital period      : {orbit.period_s / 60:.2f} min")
    print(f"eclipse fraction    : "
          f"{sum(orbit.in_eclipse(t) for t in range(0, int(orbit.period_s), 10)) / (orbit.period_s / 10):.3f}")
    print(f"passes over {site.name}: {len(passes)} in {args.days:g} day(s)")
    for aos, los in passes[:10]:
        peak = max(site.elevation_deg(orbit, t) for t in range(int(aos), int(los), 5))
        print(f"  AOS {aos / 3600:7.3f} h  LOS {los / 3600:7.3f} h  "
              f"duration {los - aos:5.0f} s  peak elevation {peak:4.1f} deg")

    t = 0.0
    while t < horizon:
        sc.step(t, args.step)
        t += args.step
    pkt = sc.emit_tm(t)
    print("\nhousekeeping sample after "
          f"{args.days:g} day(s) (APID {pkt.apid:#x}, seq {pkt.seq}):")
    for k, v in pkt.payload.items():
        print(f"  {k:22s} {v}")
    print(f"  {'auth tag':22s} {pkt.tag}")


if __name__ == "__main__":
    main()
