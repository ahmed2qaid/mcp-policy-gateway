from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path


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


class FileSchemaPinStore(SchemaPinStore):
    """Schema pin registry persisted as a small reviewed JSON artifact."""

    def __init__(self, path: str | Path) -> None:
        super().__init__()
        self.path = Path(path)

    @classmethod
    def load(cls, path: str | Path) -> "FileSchemaPinStore":
        store = cls(path)
        if not store.path.exists():
            return store
        data = json.loads(store.path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("schema registry file must contain an object")
        loaded = SchemaPinStore.from_dict(data)
        store._pins = loaded.export()
        return store

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(self.export(), indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        tmp.replace(self.path)

    def pin(self, tool: str, schema: dict) -> str:
        digest = super().pin(tool, schema)
        self.save()
        return digest
