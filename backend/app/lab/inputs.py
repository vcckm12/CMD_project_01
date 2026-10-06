"""Lab-only view of what a blocked request said (D-21: synthetic data only).

Production never stores user text in audit. The lab stack keeps the inspected messages of blocked chat
requests in API process memory (bounded, lost on restart) so a demo can show what was blocked.
"""

from __future__ import annotations

from collections import OrderedDict

MAX_EVENTS = 500
MAX_CHARS = 4000


class LabInputStore:
    def __init__(self, max_events: int = MAX_EVENTS) -> None:
        self.max_events = max_events
        self._items: OrderedDict[str, list[dict]] = OrderedDict()

    def put(self, event_id: str, messages: list[tuple[str, str]]) -> None:
        self._items[event_id] = [{"role": role, "content": content[:MAX_CHARS]} for role, content in messages]
        self._items.move_to_end(event_id)
        while len(self._items) > self.max_events:
            self._items.popitem(last=False)

    def get(self, event_id: str) -> list[dict] | None:
        return self._items.get(event_id)
