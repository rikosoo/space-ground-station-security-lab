"""Virtual clock for the discrete-event simulation.

Every component reads time from a single :class:`Clock` instance so that
experiments are deterministic and can run faster than wall time. All timestamps
in the event pipeline are *simulated* epoch seconds (float).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Clock:
    """Monotonic simulated clock.

    Attributes:
        t0: simulated epoch second at which the scenario starts.
        now: current simulated epoch second.
    """

    t0: float = 1_767_225_600.0  # 2026-01-01T00:00:00Z
    now: float = field(init=False)

    def __post_init__(self) -> None:
        self.now = self.t0

    def tick(self, seconds: float) -> float:
        self.now += seconds
        return self.now

    def elapsed(self) -> float:
        return self.now - self.t0

    def iso(self) -> str:
        import datetime as _dt

        return (
            _dt.datetime.fromtimestamp(self.now, _dt.timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )
