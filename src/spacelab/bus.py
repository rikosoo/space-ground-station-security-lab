"""In-process event bus standing in for the managed streaming tier.

In the local testbed the bus is a synchronous fan-out; in the cloud
instantiation the same events are written to Kinesis Data Streams and archived
to S3 (see ``infra/terraform``). Keeping the interface this narrow is what makes
the two deployments interchangeable for the experiment harness.
"""

from __future__ import annotations

import os
from typing import Callable, List

from .events import Event

Subscriber = Callable[[Event], None]


class EventBus:
    def __init__(self, archive_path: str | None = None) -> None:
        self._subs: List[Subscriber] = []
        self._archive_path = archive_path
        self.log: List[Event] = []
        if archive_path:
            os.makedirs(os.path.dirname(archive_path), exist_ok=True)
            # truncate any previous run
            open(archive_path, "w").close()

    def subscribe(self, fn: Subscriber) -> None:
        self._subs.append(fn)

    def publish(self, event: Event) -> None:
        self.log.append(event)
        if self._archive_path:
            with open(self._archive_path, "a") as fh:
                fh.write(event.to_json() + "\n")
        for fn in self._subs:
            fn(event)
