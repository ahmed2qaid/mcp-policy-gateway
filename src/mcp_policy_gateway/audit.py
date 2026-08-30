from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class NetworkAuditEvent:
    timestamp: str
    event: str
    upstream: str
    tool: str
    effect: str
    risk: str
    rule_id: str
    outcome: str
    duration_ms: float
    request_id: str | None = None

    @classmethod
    def now(cls, **kwargs) -> "NetworkAuditEvent":
        return cls(timestamp=datetime.now(timezone.utc).isoformat(), **kwargs)


class JsonlAuditSink:
    """Append-only structured audit sink suitable for local deployments."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def __call__(self, event: NetworkAuditEvent) -> None:
        line = json.dumps(asdict(event), ensure_ascii=False, sort_keys=True)
        with self._lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
