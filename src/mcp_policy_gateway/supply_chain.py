from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from .policy import Policy
from .registry import UpstreamConfig, UpstreamRegistry
from .schema_pin import SchemaPinStore, schema_digest


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def server_fingerprint(config: UpstreamConfig, tools: Iterable[object]) -> str:
    normalized_tools: list[dict[str, object]] = []
    for tool in tools:
        name = str(getattr(tool, "name", ""))
        schema = getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", None) or {}
        normalized_tools.append({"name": name, "schema_sha256": schema_digest(schema)})
    normalized_tools.sort(key=lambda item: str(item["name"]))
    payload = {
        "upstream": config.name,
        "transport": config.transport,
        "url": config.url,
        "command": config.command,
        "args": list(config.args),
        "tools": normalized_tools,
    }
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def detect_tool_shadowing(registry: UpstreamRegistry, discovered: dict[str, Iterable[object]]) -> tuple[str, ...]:
    issues: list[str] = []
    raw_owners: dict[str, list[str]] = {}
    exposed: set[str] = set()

    for config in registry:
        for tool in discovered.get(config.name, ()):  # type: ignore[arg-type]
            raw_name = str(getattr(tool, "name", ""))
            if not raw_name:
                issues.append(f"{config.name}: tool with empty name")
                continue
            raw_owners.setdefault(raw_name.casefold(), []).append(config.name)
            exposed_name = registry.expose(config, raw_name)
            normalized = exposed_name.casefold()
            if normalized in exposed:
                issues.append(f"exposed tool collision after case-folding: {exposed_name}")
            exposed.add(normalized)
            if raw_name.startswith(config.prefix + "__"):
                issues.append(
                    f"{config.name}:{raw_name}: raw tool name imitates the gateway namespace prefix"
                )

    for raw_name, owners in sorted(raw_owners.items()):
        if len(set(owners)) > 1:
            issues.append(
                f"raw tool name '{raw_name}' is published by multiple upstreams: {', '.join(sorted(set(owners)))}"
            )
    return tuple(issues)


@dataclass(frozen=True)
class SignedSchemaManifest:
    version: int
    pins: dict[str, str]
    fingerprints: dict[str, str]
    signature: str

    @classmethod
    def issue(
        cls,
        *,
        pins: SchemaPinStore,
        fingerprints: dict[str, str],
        secret: bytes,
    ) -> "SignedSchemaManifest":
        payload = {
            "version": 1,
            "pins": pins.export(),
            "fingerprints": dict(sorted(fingerprints.items())),
        }
        signature = hmac.new(secret, _canonical_json(payload), hashlib.sha256).hexdigest()
        return cls(signature=signature, **payload)

    @classmethod
    def from_dict(cls, data: dict) -> "SignedSchemaManifest":
        if int(data.get("version", 0)) != 1:
            raise ValueError("unsupported signed schema manifest version")
        pins = data.get("pins", {})
        fingerprints = data.get("fingerprints", {})
        signature = str(data.get("signature", ""))
        if not isinstance(pins, dict) or not isinstance(fingerprints, dict) or len(signature) != 64:
            raise ValueError("invalid signed schema manifest")
        SchemaPinStore.from_dict(pins)
        for upstream, digest in fingerprints.items():
            value = str(digest).lower()
            if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
                raise ValueError(f"invalid upstream fingerprint for {upstream}")
        return cls(
            version=1,
            pins={str(k): str(v).lower() for k, v in pins.items()},
            fingerprints={str(k): str(v).lower() for k, v in fingerprints.items()},
            signature=signature.lower(),
        )

    def verify(self, secret: bytes) -> bool:
        payload = {
            "version": self.version,
            "pins": dict(sorted(self.pins.items())),
            "fingerprints": dict(sorted(self.fingerprints.items())),
        }
        expected = hmac.new(secret, _canonical_json(payload), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected)

    def to_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "pins": dict(sorted(self.pins.items())),
            "fingerprints": dict(sorted(self.fingerprints.items())),
            "signature": self.signature,
        }


@dataclass(frozen=True)
class PolicyBundle:
    bundle_id: str
    version: str
    policy: dict
    schema_pins: dict[str, str]
    upstream_fingerprints: dict[str, str]

    @classmethod
    def from_dict(cls, data: dict) -> "PolicyBundle":
        bundle_id = str(data.get("id", "")).strip()
        version = str(data.get("version", "")).strip()
        policy = data.get("policy", {})
        pins = data.get("schema_pins", {})
        fingerprints = data.get("upstream_fingerprints", {})
        if not bundle_id or not version:
            raise ValueError("policy bundle id and version are required")
        if not isinstance(policy, dict) or not isinstance(pins, dict) or not isinstance(fingerprints, dict):
            raise ValueError("policy bundle policy, schema_pins, and upstream_fingerprints must be objects")
        Policy.from_dict(policy)
        SchemaPinStore.from_dict(pins)
        return cls(
            bundle_id=bundle_id,
            version=version,
            policy=policy,
            schema_pins={str(k): str(v) for k, v in pins.items()},
            upstream_fingerprints={str(k): str(v) for k, v in fingerprints.items()},
        )


@dataclass(frozen=True)
class ConfigFinding:
    severity: str
    code: str
    message: str


def scan_gateway_config(config: dict, *, root: Path | None = None) -> tuple[ConfigFinding, ...]:
    findings: list[ConfigFinding] = []
    root = root or Path.cwd()
    raw_upstreams = config.get("upstreams", {})
    try:
        registry = UpstreamRegistry.from_dict(raw_upstreams)
    except Exception as exc:
        return (ConfigFinding("critical", "config.invalid_upstreams", str(exc)),)

    policy_data = config.get("policy")
    if policy_data is None and config.get("policy_file"):
        policy_path = root / str(config["policy_file"])
        try:
            policy_data = json.loads(policy_path.read_text(encoding="utf-8"))
        except Exception as exc:
            findings.append(ConfigFinding("critical", "config.policy_unreadable", str(exc)))
    if not isinstance(policy_data, dict):
        findings.append(ConfigFinding("critical", "config.policy_missing", "gateway policy could not be loaded"))
    else:
        try:
            policy = Policy.from_dict(policy_data)
            if policy.default == "allow":
                findings.append(
                    ConfigFinding("high", "policy.default_allow", "default allow weakens the zero-trust boundary")
                )
        except Exception as exc:
            findings.append(ConfigFinding("critical", "policy.invalid", str(exc)))

    for upstream in registry:
        if upstream.transport == "http":
            parsed = urlparse(str(upstream.url))
            if parsed.scheme != "https" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
                findings.append(
                    ConfigFinding(
                        "high",
                        "upstream.insecure_http",
                        f"{upstream.name}: remote MCP upstream does not use HTTPS",
                    )
                )
            if not upstream.bearer_token_env and not upstream.headers_from_env:
                findings.append(
                    ConfigFinding(
                        "medium",
                        "upstream.no_auth",
                        f"{upstream.name}: HTTP upstream has no environment-backed authentication",
                    )
                )
        for key, value in upstream.env.items():
            if any(marker in key.lower() for marker in ("token", "secret", "password", "api_key", "apikey")) and value:
                findings.append(
                    ConfigFinding(
                        "critical",
                        "upstream.inline_secret",
                        f"{upstream.name}: secret-looking environment variable '{key}' is stored inline",
                    )
                )

    pins = config.get("schema_pins", {})
    if not pins:
        findings.append(ConfigFinding("medium", "schema.unpinned", "no schema pins are configured"))
    elif not bool(config.get("enforce_schema_pins", False)):
        findings.append(
            ConfigFinding("medium", "schema.not_enforced", "schema pins exist but enforcement is disabled")
        )

    if bool(config.get("auto_pin", False)) and bool(config.get("enforce_schema_pins", False)):
        findings.append(
            ConfigFinding(
                "medium",
                "schema.auto_pin_with_enforcement",
                "auto-pin can silently establish trust; prefer an explicit reviewed pin manifest in CI",
            )
        )
    return tuple(findings)


def secret_from_env(name: str) -> bytes:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"missing signing secret environment variable: {name}")
    return value.encode("utf-8")
