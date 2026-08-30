from __future__ import annotations

import asyncio
import os
import time
from contextlib import asynccontextmanager

import httpx2
from mcp import Client, StdioServerParameters
from mcp.client.streamable_http import streamable_http_client

from .registry import UpstreamConfig


class CircuitOpenError(RuntimeError):
    pass


class CircuitBreaker:
    def __init__(self, failure_threshold: int, recovery_seconds: float) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_seconds = recovery_seconds
        self.failures = 0
        self.open_until = 0.0

    def before_call(self) -> None:
        now = time.monotonic()
        if self.open_until and now < self.open_until:
            raise CircuitOpenError("upstream circuit is open")
        if self.open_until and now >= self.open_until:
            self.open_until = 0.0
            self.failures = 0

    def success(self) -> None:
        self.failures = 0
        self.open_until = 0.0

    def failure(self) -> None:
        self.failures += 1
        if self.failures >= self.failure_threshold:
            self.open_until = time.monotonic() + self.recovery_seconds


class SDKConnector:
    """Connect to real MCP upstreams using the official MCP Python SDK v2."""

    @asynccontextmanager
    async def _client(self, config: UpstreamConfig):
        if config.transport == "http":
            headers: dict[str, str] = {}
            if config.bearer_token_env:
                token = os.getenv(config.bearer_token_env)
                if not token:
                    raise RuntimeError(f"missing environment variable: {config.bearer_token_env}")
                headers["Authorization"] = f"Bearer {token}"
            for header, env_name in config.headers_from_env.items():
                value = os.getenv(env_name)
                if not value:
                    raise RuntimeError(f"missing environment variable: {env_name}")
                headers[header] = value

            timeout = httpx2.Timeout(config.timeout_seconds, read=max(config.timeout_seconds, 300.0))
            async with httpx2.AsyncClient(headers=headers, timeout=timeout, follow_redirects=True) as http_client:
                transport = streamable_http_client(str(config.url), http_client=http_client)
                async with Client(transport) as client:
                    yield client
            return

        env = dict(config.env)
        for name in config.env_passthrough:
            if name in os.environ:
                env[name] = os.environ[name]
        params = StdioServerParameters(command=str(config.command), args=list(config.args), env=env or None)
        async with Client(params) as client:
            yield client

    async def list_tools(self, config: UpstreamConfig):
        async def operation():
            async with self._client(config) as client:
                result = await client.list_tools()
                return list(result.tools)

        return await asyncio.wait_for(operation(), timeout=config.timeout_seconds)

    async def call_tool(self, config: UpstreamConfig, name: str, arguments: dict):
        async def operation():
            async with self._client(config) as client:
                return await client.call_tool(name, arguments)

        return await asyncio.wait_for(operation(), timeout=config.timeout_seconds)
