from __future__ import annotations

import unittest
from contextlib import asynccontextmanager
from types import SimpleNamespace

from mcp_policy_gateway.registry import UpstreamConfig
from mcp_policy_gateway.transport import SDKConnector


class _FakeClient:
    def __init__(self) -> None:
        self.calls = 0

    async def list_tools(self):
        self.calls += 1
        return SimpleNamespace(tools=[SimpleNamespace(name="ping")])

    async def call_tool(self, name: str, arguments: dict):
        self.calls += 1
        return {"name": name, "arguments": arguments}


class _CountingConnector(SDKConnector):
    def __init__(self) -> None:
        super().__init__()
        self.opens = 0
        self.closes = 0
        self.client = _FakeClient()

    @asynccontextmanager
    async def _open_client(self, config: UpstreamConfig):
        self.opens += 1
        try:
            yield self.client
        finally:
            self.closes += 1


class PersistentSessionTests(unittest.IsolatedAsyncioTestCase):
    async def test_persistent_upstream_reuses_one_initialized_client(self):
        connector = _CountingConnector()
        config = UpstreamConfig(
            name="api",
            transport="http",
            prefix="api",
            url="http://example.test/mcp",
            persistent_session=True,
        )

        await connector.list_tools(config)
        await connector.call_tool(config, "ping", {"value": 1})
        await connector.list_tools(config)

        self.assertEqual(connector.opens, 1)
        self.assertEqual(connector.closes, 0)
        self.assertEqual(connector.client.calls, 3)

        await connector.aclose()
        self.assertEqual(connector.closes, 1)

    async def test_ephemeral_upstream_opens_per_operation(self):
        connector = _CountingConnector()
        config = UpstreamConfig(
            name="legacy",
            transport="http",
            prefix="legacy",
            url="http://example.test/mcp",
            persistent_session=False,
        )

        await connector.list_tools(config)
        await connector.call_tool(config, "ping", {})

        self.assertEqual(connector.opens, 2)
        self.assertEqual(connector.closes, 2)

    async def test_close_upstream_forces_clean_reconnect(self):
        connector = _CountingConnector()
        config = UpstreamConfig(
            name="api",
            transport="http",
            prefix="api",
            url="http://example.test/mcp",
            persistent_session=True,
        )

        await connector.list_tools(config)
        await connector.close_upstream("api")
        await connector.list_tools(config)

        self.assertEqual(connector.opens, 2)
        self.assertEqual(connector.closes, 1)
        await connector.aclose()
        self.assertEqual(connector.closes, 2)


if __name__ == "__main__":
    unittest.main()
