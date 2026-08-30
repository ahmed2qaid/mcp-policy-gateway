from __future__ import annotations

import time
from typing import Any, Protocol

import mcp.types as types

from .audit import NetworkAuditEvent
from .policy import Decision, PolicyEngine
from .registry import UpstreamConfig, UpstreamRegistry
from .schema_pin import SchemaPinStore
from .security import (
    AgentIdentity,
    ApprovalTokenSigner,
    EgressPolicy,
    SlidingWindowRateLimiter,
    arguments_digest,
    prompt_injection_signals,
)
from .transport import CircuitBreaker, CircuitOpenError


class Connector(Protocol):
    async def list_tools(self, config: UpstreamConfig): ...
    async def call_tool(self, config: UpstreamConfig, name: str, arguments: dict): ...


class PolicyGatewayService:
    def __init__(
        self,
        engine: PolicyEngine,
        registry: UpstreamRegistry,
        connector: Connector,
        *,
        schema_pins: SchemaPinStore | None = None,
        enforce_schema_pins: bool = False,
        auto_pin: bool = False,
        audit_sink=None,
        approval_signer: ApprovalTokenSigner | None = None,
        rate_limiter: SlidingWindowRateLimiter | None = None,
        egress_policy: EgressPolicy | None = None,
        prompt_injection_review: bool = True,
    ) -> None:
        self.engine = engine
        self.registry = registry
        self.connector = connector
        self.schema_pins = schema_pins or SchemaPinStore()
        self.enforce_schema_pins = enforce_schema_pins
        self.auto_pin = auto_pin
        self.audit_sink = audit_sink
        self.approval_signer = approval_signer
        self.rate_limiter = rate_limiter
        self.egress_policy = egress_policy
        self.prompt_injection_review = prompt_injection_review
        self.breakers = {
            config.name: CircuitBreaker(config.failure_threshold, config.recovery_seconds)
            for config in registry
        }

    async def list_tools(self) -> list[types.Tool]:
        exposed_tools: list[types.Tool] = []
        for config in self.registry:
            breaker = self.breakers[config.name]
            try:
                breaker.before_call()
                tools = await self.connector.list_tools(config)
                breaker.success()
            except Exception as exc:
                if not isinstance(exc, CircuitOpenError):
                    breaker.failure()
                self._audit(config, "", Decision("deny", "high", "upstream", str(exc)), "list-failed", 0.0)
                continue

            for tool in tools:
                exposed_name = self.registry.expose(config, tool.name)
                schema = getattr(tool, "input_schema", None) or {}
                verification = self.schema_pins.verify(exposed_name, schema)
                if verification.expected is None and self.auto_pin:
                    self.schema_pins.pin(exposed_name, schema)
                elif verification.expected is not None and not verification.trusted:
                    self._audit(
                        config,
                        exposed_name,
                        Decision("deny", "critical", "schema-pin", "tool schema changed"),
                        "schema-drift",
                        0.0,
                    )
                    if self.enforce_schema_pins:
                        continue

                exposed_tools.append(tool.model_copy(update={"name": exposed_name}))
        return exposed_tools

    async def call_tool(
        self,
        exposed_name: str,
        arguments: dict,
        *,
        request_id: object | None = None,
        identity: AgentIdentity | None = None,
        approval_token: str | None = None,
    ) -> Any:
        identity = identity or AgentIdentity.anonymous()
        try:
            config, raw_name = self.registry.resolve_tool(exposed_name)
        except KeyError as exc:
            return self._tool_error(str(exc), {"code": "gateway.unknown_tool"})

        if self.rate_limiter is not None:
            allowed, retry_after = self.rate_limiter.allow(identity, exposed_name)
            if not allowed:
                decision = Decision("deny", "high", "rate-limit", "agent/tool rate limit exceeded")
                self._audit(config, exposed_name, decision, "rate-limited", 0.0, request_id)
                return self._tool_error(
                    "tool call rate limited",
                    {"code": "gateway.rate_limited", "retry_after_seconds": round(retry_after, 3)},
                )

        if self.egress_policy is not None:
            blocked_hosts = self.egress_policy.violations(arguments)
            if blocked_hosts:
                decision = Decision("deny", "critical", "egress", "destination host is not allowlisted")
                self._audit(config, exposed_name, decision, "egress-denied", 0.0, request_id)
                return self._tool_error(
                    "tool call blocked by egress policy",
                    {"code": "gateway.egress_denied", "hosts": list(blocked_hosts)},
                )

        signals = prompt_injection_signals(arguments) if self.prompt_injection_review else ()
        if signals:
            decision = Decision("approval", "high", "prompt-injection", ", ".join(signals))
        else:
            decision = self.engine.evaluate(exposed_name, arguments, identity)

        if decision.effect == "approval" and self._approval_valid(
            approval_token, exposed_name, arguments, identity
        ):
            decision = Decision(
                "allow",
                decision.risk,
                f"approved:{decision.rule_id}",
                "signed human approval verified",
            )

        if decision.effect == "deny":
            self._audit(config, exposed_name, decision, "denied", 0.0, request_id)
            return self._tool_error("tool call denied by gateway policy", {"decision": decision.__dict__})
        if decision.effect == "approval":
            self._audit(config, exposed_name, decision, "approval-required", 0.0, request_id)
            return self._tool_error(
                "human approval required",
                {
                    "approval_required": True,
                    "tool": exposed_name,
                    "arguments_sha256": arguments_digest(arguments),
                    "agent_id": identity.agent_id,
                    "tenant": identity.tenant,
                    "decision": decision.__dict__,
                },
            )

        breaker = self.breakers[config.name]
        started = time.perf_counter()
        try:
            breaker.before_call()
            result = await self.connector.call_tool(config, raw_name, arguments)
            breaker.success()
            self._audit(config, exposed_name, decision, "forwarded", (time.perf_counter() - started) * 1000, request_id)
            return result
        except CircuitOpenError as exc:
            self._audit(config, exposed_name, decision, "circuit-open", 0.0, request_id)
            return self._tool_error(str(exc), {"code": "gateway.circuit_open", "upstream": config.name})
        except Exception as exc:
            breaker.failure()
            self._audit(config, exposed_name, decision, "upstream-error", (time.perf_counter() - started) * 1000, request_id)
            return self._tool_error(
                "upstream MCP server failed",
                {"code": "gateway.upstream_error", "upstream": config.name, "detail": str(exc)},
            )

    def _approval_valid(self, token: str | None, tool: str, arguments: dict, identity: AgentIdentity) -> bool:
        return bool(
            token
            and self.approval_signer is not None
            and self.approval_signer.verify(
                token,
                tool=tool,
                arguments=arguments,
                identity=identity,
            )
        )

    def _audit(
        self,
        config: UpstreamConfig,
        tool: str,
        decision: Decision,
        outcome: str,
        duration_ms: float,
        request_id: object | None = None,
    ) -> None:
        if self.audit_sink is None:
            return
        self.audit_sink(
            NetworkAuditEvent.now(
                event="tool-decision" if tool else "upstream-health",
                upstream=config.name,
                tool=tool,
                effect=decision.effect,
                risk=decision.risk,
                rule_id=decision.rule_id,
                outcome=outcome,
                duration_ms=round(duration_ms, 3),
                request_id=None if request_id is None else str(request_id),
            )
        )

    @staticmethod
    def _tool_error(message: str, metadata: dict) -> types.CallToolResult:
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=message)],
            is_error=True,
            _meta={"mcp-policy-gateway/error": metadata},
        )
