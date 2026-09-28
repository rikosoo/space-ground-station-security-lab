"""Principals suspended by automated response.

Automated containment blocks a principal, and the obvious implementation is a
set of names. A set has no notion of when the block was applied, so it never
lifts, and that turns out to matter for two separate reasons.

The operational one is that a block applied by a false positive is a denial of
service against a legitimate operator, for as long as the system runs. At the
false-positive rate this pack reports, several benign accounts are suspended
over a one-week window.

The measurement one is subtler. A blocked principal stops producing events, so
the account disappears from the telemetry along with the adversary's access to
it. An attack that later targets that account produces no authentication event
for the behavioural rules to evaluate, and detection falls back to a slower
path. Containing one attack degrades the observability of the next.

Both follow from the block being permanent, so the block carries an expiry: a
suspension the SOC lifts after triage, rather than an account that is deleted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterator

#: How long an automated block holds before it lifts, in seconds. A day is long
#: enough to outlast any of the attacks modelled here -- containment still does
#: its job -- and short enough that a wrongly suspended operator is working
#: again by the next shift.
DEFAULT_BLOCK_TTL_S = 86_400.0


@dataclass
class BlockList:
    """The set of currently blocked principals, keyed by when each block ends.

    ``ttl_s`` of ``None`` restores the old behaviour of a block that never
    lifts, which the ablation uses to measure what the expiry is worth.
    """

    ttl_s: float | None = DEFAULT_BLOCK_TTL_S
    until: Dict[str, float] = field(default_factory=dict)

    def add(self, principal: str, t: float) -> None:
        """Block ``principal`` from time ``t``.

        A repeat block restarts the clock rather than extending the old expiry,
        so a principal that keeps tripping a rule stays blocked, but one that
        tripped it twice an hour ago is not held for twice as long.
        """
        self.until[principal] = (
            float("inf") if self.ttl_s is None else t + self.ttl_s)

    def blocked(self, principal: str, t: float) -> bool:
        expiry = self.until.get(principal)
        if expiry is None:
            return False
        if t >= expiry:
            del self.until[principal]
            return False
        return True

    def active(self, t: float) -> Iterator[str]:
        return (p for p, expiry in self.until.items() if t < expiry)

    def __len__(self) -> int:
        return len(self.until)
