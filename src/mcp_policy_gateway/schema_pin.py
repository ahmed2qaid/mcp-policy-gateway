from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass


def schema_digest(schema: dict) -> str:
    canonical = json.dumps(schema, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SchemaVerification:
    tool: str
    expected: str | None
    actual: str
    trusted: bool


class SchemaPinStore:
    def __init__(self) -> None:
        self._pins: dict[str, str] = {}

    def pin(self, tool: str, schema: dict) -> str:
        if not tool:
            raise ValueError("tool name must not be empty")
        digest = schema_digest(schema)
        self._pins[tool] = digest
        return digest

    def verify(self, tool: str, schema: dict) -> SchemaVerification:
        actual = schema_digest(schema)
        expected = self._pins.get(tool)
        return SchemaVerification(
            tool=tool,
            expected=expected,
            actual=actual,
            trusted=expected is not None and expected == actual,
        )

    def export(self) -> dict[str, str]:
        return dict(sorted(self._pins.items()))
