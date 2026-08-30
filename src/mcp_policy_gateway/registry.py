from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class UpstreamConfig:
    name: str
    transport: str
    prefix: str
    url: str | None = None
    command: str | None = None
    args: tuple[str, ...] = ()
    env: dict[str, str] = field(default_factory=dict)
    env_passthrough: tuple[str, ...] = ()
    bearer_token_env: str | None = None
    headers_from_env: dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 30.0
    failure_threshold: int = 3
    recovery_seconds: float = 30.0
    persistent_session: bool = True

    @classmethod
    def from_dict(cls, name: str, data: dict) -> "UpstreamConfig":
        if not isinstance(data, dict):
            raise ValueError(f"upstream '{name}' must be an object")
        transport = str(data.get("transport", "")).strip().lower()
        if transport not in {"http", "stdio"}:
            raise ValueError(f"upstream '{name}' transport must be 'http' or 'stdio'")

        prefix = str(data.get("prefix", name)).strip()
        if not prefix or "__" in prefix:
            raise ValueError(f"upstream '{name}' prefix must be non-empty and cannot contain '__'")

        url = data.get("url")
        command = data.get("command")
        if transport == "http" and not isinstance(url, str):
            raise ValueError(f"HTTP upstream '{name}' requires url")
        if transport == "stdio" and not isinstance(command, str):
            raise ValueError(f"stdio upstream '{name}' requires command")

        timeout = float(data.get("timeout_seconds", 30.0))
        threshold = int(data.get("failure_threshold", 3))
        recovery = float(data.get("recovery_seconds", 30.0))
        if timeout <= 0 or threshold <= 0 or recovery <= 0:
            raise ValueError("timeout, failure_threshold, and recovery_seconds must be positive")

        env = data.get("env", {})
        passthrough = data.get("env_passthrough", [])
        headers = data.get("headers_from_env", {})
        if not isinstance(env, dict) or not isinstance(passthrough, list) or not isinstance(headers, dict):
            raise ValueError("env and headers_from_env must be objects; env_passthrough must be a list")

        persistent = data.get("persistent_session", True)
        if not isinstance(persistent, bool):
            raise ValueError("persistent_session must be a boolean")

        return cls(
            name=name,
            transport=transport,
            prefix=prefix,
            url=url,
            command=command,
            args=tuple(str(x) for x in data.get("args", [])),
            env={str(k): str(v) for k, v in env.items()},
            env_passthrough=tuple(str(x) for x in passthrough),
            bearer_token_env=(str(data["bearer_token_env"]) if data.get("bearer_token_env") else None),
            headers_from_env={str(k): str(v) for k, v in headers.items()},
            timeout_seconds=timeout,
            failure_threshold=threshold,
            recovery_seconds=recovery,
            persistent_session=persistent,
        )


class UpstreamRegistry:
    def __init__(self, configs: tuple[UpstreamConfig, ...]) -> None:
        self._by_name = {item.name: item for item in configs}
        self._by_prefix: dict[str, UpstreamConfig] = {}
        if len(self._by_name) != len(configs):
            raise ValueError("duplicate upstream name")
        for item in configs:
            if item.prefix in self._by_prefix:
                raise ValueError(f"duplicate upstream prefix: {item.prefix}")
            self._by_prefix[item.prefix] = item

    @classmethod
    def from_dict(cls, data: dict) -> "UpstreamRegistry":
        if not isinstance(data, dict) or not data:
            raise ValueError("at least one upstream server is required")
        return cls(tuple(UpstreamConfig.from_dict(str(name), cfg) for name, cfg in data.items()))

    def __iter__(self):
        return iter(self._by_name.values())

    def expose(self, config: UpstreamConfig, raw_tool_name: str) -> str:
        if not raw_tool_name:
            raise ValueError("raw tool name must not be empty")
        return f"{config.prefix}__{raw_tool_name}"

    def resolve_tool(self, exposed_name: str) -> tuple[UpstreamConfig, str]:
        if "__" not in exposed_name:
            raise KeyError(f"tool '{exposed_name}' is not namespaced")
        prefix, raw_name = exposed_name.split("__", 1)
        config = self._by_prefix.get(prefix)
        if config is None or not raw_name:
            raise KeyError(f"unknown gateway tool: {exposed_name}")
        return config, raw_name
