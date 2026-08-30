from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any
from urllib.parse import urlparse


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    tenant: str = "default"
    roles: tuple[str, ...] = ()

    @classmethod
    def anonymous(cls) -> "AgentIdentity":
        return cls("anonymous")


def arguments_digest(arguments: dict[str, Any]) -> str:
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class ApprovalTokenSigner:
    """Short-lived HMAC approval tokens bound to agent, tool and arguments."""

    def __init__(self, secret: str | bytes) -> None:
        raw = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
        if len(raw) < 16:
            raise ValueError("approval secret must be at least 16 bytes")
        self._secret = raw

    def issue(self, *, tool: str, arguments: dict, identity: AgentIdentity, ttl_seconds: int = 300, now: int | None = None) -> str:
        issued = int(time.time() if now is None else now)
        payload = {
            "v": 1,
            "tool": tool,
            "arguments_sha256": arguments_digest(arguments),
            "agent_id": identity.agent_id,
            "tenant": identity.tenant,
            "iat": issued,
            "exp": issued + ttl_seconds,
        }
        body = _b64e(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        sig = _b64e(hmac.new(self._secret, body.encode("ascii"), hashlib.sha256).digest())
        return f"{body}.{sig}"

    def verify(self, token: str, *, tool: str, arguments: dict, identity: AgentIdentity, now: int | None = None) -> bool:
        try:
            body, sig = token.split(".", 1)
            expected = _b64e(hmac.new(self._secret, body.encode("ascii"), hashlib.sha256).digest())
            if not hmac.compare_digest(sig, expected):
                return False
            payload = json.loads(_b64d(body))
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            return False
        current = int(time.time() if now is None else now)
        return (
            payload.get("v") == 1
            and payload.get("tool") == tool
            and payload.get("arguments_sha256") == arguments_digest(arguments)
            and payload.get("agent_id") == identity.agent_id
            and payload.get("tenant") == identity.tenant
            and isinstance(payload.get("exp"), int)
            and current <= payload["exp"]
        )


class SlidingWindowRateLimiter:
    def __init__(self, max_calls: int = 60, window_seconds: float = 60.0) -> None:
        if max_calls < 1 or window_seconds <= 0:
            raise ValueError("invalid rate limit")
        self.max_calls = max_calls
        self.window_seconds = float(window_seconds)
        self._events: dict[tuple[str, str, str], deque[float]] = defaultdict(deque)

    def allow(self, identity: AgentIdentity, tool: str, *, now: float | None = None) -> tuple[bool, float]:
        current = time.monotonic() if now is None else float(now)
        key = (identity.tenant, identity.agent_id, tool)
        events = self._events[key]
        cutoff = current - self.window_seconds
        while events and events[0] <= cutoff:
            events.popleft()
        if len(events) >= self.max_calls:
            return False, max(0.0, self.window_seconds - (current - events[0]))
        events.append(current)
        return True, 0.0


class EgressPolicy:
    def __init__(self, allowed_hosts: tuple[str, ...] = ()) -> None:
        self.allowed_hosts = allowed_hosts

    def violations(self, arguments: Any) -> tuple[str, ...]:
        if not self.allowed_hosts:
            return ()
        blocked: set[str] = set()
        for value in _walk_strings(arguments):
            if value.lower().startswith(("http://", "https://")):
                host = (urlparse(value).hostname or "").lower()
                if host and not any(fnmatchcase(host, pattern.lower()) for pattern in self.allowed_hosts):
                    blocked.add(host)
        return tuple(sorted(blocked))


_INJECTION = (
    re.compile(r"\bignore\s+(all\s+)?previous\b", re.I),
    re.compile(r"\b(system|developer)\s+prompt\b", re.I),
    re.compile(r"\breveal\s+(the\s+)?(secret|credential|token|key)s?\b", re.I),
    re.compile(r"\bbypass\s+(the\s+)?(policy|guardrail|approval)\b", re.I),
)


def prompt_injection_signals(arguments: Any) -> tuple[str, ...]:
    found: set[str] = set()
    for value in _walk_strings(arguments):
        for index, pattern in enumerate(_INJECTION, start=1):
            if pattern.search(value):
                found.add(f"prompt-injection-{index}")
    return tuple(sorted(found))


_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])")
_SECRET = re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|secret|password)\b\s*[:=]\s*[\"']?([A-Za-z0-9_./+=-]{8,})")


def redact_sensitive(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: redact_sensitive(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, str):
        value = _EMAIL.sub("[REDACTED_EMAIL]", value)
        return _SECRET.sub(lambda m: f"{m.group(1)}=[REDACTED_SECRET]", value)
    return value


def _walk_strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _walk_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _walk_strings(item)
