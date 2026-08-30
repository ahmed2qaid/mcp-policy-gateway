from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase

_ALLOWED_EFFECTS = {"allow", "deny", "approval"}
_ALLOWED_RISKS = {"low", "medium", "high", "critical"}


@dataclass(frozen=True)
class Rule:
    id: str
    tool: str
    effect: str
    risk: str = "medium"
    reason: str = ""
    agents: tuple[str, ...] = ()
    roles_any: tuple[str, ...] = ()
    argument_equals: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class Decision:
    effect: str
    risk: str
    rule_id: str
    reason: str

    @property
    def allowed(self) -> bool:
        return self.effect == "allow"

    @property
    def requires_approval(self) -> bool:
        return self.effect == "approval"


class Policy:
    def __init__(self, *, default: str, rules: tuple[Rule, ...]) -> None:
        if default not in _ALLOWED_EFFECTS:
            raise ValueError(f"invalid default effect: {default}")
        self.default = default
        self.rules = rules

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        default = str(data.get("default", "deny"))
        raw_rules = data.get("rules", [])
        if not isinstance(raw_rules, list):
            raise ValueError("policy.rules must be a list")

        rules: list[Rule] = []
        seen: set[str] = set()
        for item in raw_rules:
            if not isinstance(item, dict):
                raise ValueError("each policy rule must be an object")
            rule_id = str(item.get("id", "")).strip()
            tool = str(item.get("tool", "")).strip()
            effect = str(item.get("effect", "")).strip()
            risk = str(item.get("risk", "medium")).strip()
            if not rule_id or not tool:
                raise ValueError("rule id and tool pattern are required")
            if rule_id in seen:
                raise ValueError(f"duplicate rule id: {rule_id}")
            if effect not in _ALLOWED_EFFECTS:
                raise ValueError(f"invalid rule effect: {effect}")
            if risk not in _ALLOWED_RISKS:
                raise ValueError(f"invalid rule risk: {risk}")
            argument_equals = item.get("argument_equals", {})
            if not isinstance(argument_equals, dict):
                raise ValueError("argument_equals must be an object")
            seen.add(rule_id)
            rules.append(
                Rule(
                    id=rule_id,
                    tool=tool,
                    effect=effect,
                    risk=risk,
                    reason=str(item.get("reason", "")),
                    agents=tuple(str(v) for v in item.get("agents", [])),
                    roles_any=tuple(str(v) for v in item.get("roles_any", [])),
                    argument_equals=dict(argument_equals),
                )
            )
        return cls(default=default, rules=tuple(rules))


class PolicyEngine:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def evaluate(self, tool_name: str, arguments: dict | None = None, identity=None) -> Decision:
        if not tool_name:
            return Decision("deny", "critical", "invalid-tool", "tool name is empty")
        arguments = arguments or {}

        for rule in self.policy.rules:
            if not fnmatchcase(tool_name, rule.tool):
                continue
            if rule.agents:
                agent_id = getattr(identity, "agent_id", "anonymous")
                if not any(fnmatchcase(agent_id, pattern) for pattern in rule.agents):
                    continue
            if rule.roles_any:
                roles = set(getattr(identity, "roles", ()))
                if not roles.intersection(rule.roles_any):
                    continue
            if rule.argument_equals and not all(
                _get_path(arguments, path) == expected
                for path, expected in rule.argument_equals.items()
            ):
                continue
            return Decision(
                effect=rule.effect,
                risk=rule.risk,
                rule_id=rule.id,
                reason=rule.reason or f"matched policy rule '{rule.id}'",
            )

        return Decision(
            effect=self.policy.default,
            risk="medium" if self.policy.default == "allow" else "high",
            rule_id="default",
            reason="no explicit rule matched",
        )


def _get_path(arguments: dict, path: str):
    current: object = arguments
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current
