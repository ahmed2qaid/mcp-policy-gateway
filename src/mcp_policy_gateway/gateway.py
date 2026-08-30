from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Callable

from .policy import Decision, PolicyEngine


@dataclass(frozen=True)
class AuditEvent:
    timestamp: str
    request_id: object
    tool: str
    effect: str
    risk: str
    rule_id: str
    reason: str


Upstream = Callable[[dict], dict]
AuditSink = Callable[[AuditEvent], None]


class PolicyGateway:
    def __init__(self, engine: PolicyEngine, *, audit_sink: AuditSink | None = None) -> None:
        self.engine = engine
        self.audit_sink = audit_sink

    def handle(self, message: dict, upstream: Upstream) -> dict:
        if message.get("method") != "tools/call":
            return upstream(message)

        params = message.get("params") or {}
        if not isinstance(params, dict):
            return self._error(message, -32602, "invalid tools/call params")

        tool = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(tool, str) or not isinstance(arguments, dict):
            return self._error(message, -32602, "tools/call requires a tool name and object arguments")

        decision = self.engine.evaluate(tool, arguments)
        self._audit(message.get("id"), tool, decision)

        if decision.effect == "deny":
            return self._error(
                message,
                -32001,
                "tool call denied by policy",
                {"decision": asdict(decision)},
            )

        if decision.effect == "approval":
            return self._error(
                message,
                -32002,
                "human approval required",
                {
                    "approval_required": True,
                    "tool": tool,
                    "arguments": arguments,
                    "decision": asdict(decision),
                },
            )

        return upstream(message)

    def _audit(self, request_id: object, tool: str, decision: Decision) -> None:
        if self.audit_sink is None:
            return
        self.audit_sink(
            AuditEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                request_id=request_id,
                tool=tool,
                effect=decision.effect,
                risk=decision.risk,
                rule_id=decision.rule_id,
                reason=decision.reason,
            )
        )

    @staticmethod
    def _error(message: dict, code: int, text: str, data: dict | None = None) -> dict:
        error = {"code": code, "message": text}
        if data is not None:
            error["data"] = data
        return {
            "jsonrpc": message.get("jsonrpc", "2.0"),
            "id": message.get("id"),
            "error": error,
        }
