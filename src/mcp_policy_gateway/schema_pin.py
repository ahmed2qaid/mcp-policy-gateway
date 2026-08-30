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

    @classmethod
    def from_dict(cls, pins: dict | None) -> "SchemaPinStore":
        store = cls()
        if pins is None:
            return store
        if not isinstance(pins, dict):
            raise ValueError("schema_pins must be an object")
        for tool, digest in pins.items():
            value = str(digest).lower()
            if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
                raise ValueError(f"invalid schema digest for {tool}")
            store._pins[str(tool)] = value
        return store

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
