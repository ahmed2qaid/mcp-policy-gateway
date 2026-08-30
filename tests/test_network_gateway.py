import asyncio
import unittest

import mcp.types as types
from mcp import Client

from mcp_policy_gateway.policy import Policy, PolicyEngine
from mcp_policy_gateway.registry import UpstreamConfig, UpstreamRegistry
from mcp_policy_gateway.server import PolicyMCPServer
from mcp_policy_gateway.service import PolicyGatewayService


class FakeConnector:
    def __init__(self):
        self.calls = 0
        self.fail = False

    async def list_tools(self, config):
        return [
            types.Tool(
                name="read",
                description="Read a record",
                inputSchema={"type": "object", "properties": {}},
            )
        ]

    async def call_tool(self, config, name, arguments):
        self.calls += 1
        if self.fail:
            raise RuntimeError("boom")
        return types.CallToolResult(content=[types.TextContent(type="text", text=f"{config.name}:{name}")])


def make_service(connector=None, *, failure_threshold=3):
    config = UpstreamConfig(
        name="database",
        transport="http",
        prefix="db",
        url="http://example.invalid/mcp",
        failure_threshold=failure_threshold,
        recovery_seconds=60,
    )
    registry = UpstreamRegistry((config,))
    policy = Policy.from_dict(
        {
            "default": "deny",
            "rules": [
                {"id": "read", "tool": "db__read", "effect": "allow", "risk": "low"},
                {"id": "delete", "tool": "db__delete", "effect": "deny", "risk": "critical"},
            ],
        }
    )
    return PolicyGatewayService(PolicyEngine(policy), registry, connector or FakeConnector())


class NetworkGatewayTests(unittest.TestCase):
    def test_tools_are_namespaced(self):
        service = make_service()
        tools = asyncio.run(service.list_tools())
        self.assertEqual([tool.name for tool in tools], ["db__read"])

    def test_policy_blocks_before_upstream(self):
        connector = FakeConnector()
        service = make_service(connector)
        result = asyncio.run(service.call_tool("db__delete", {}))
        self.assertTrue(result.is_error)
        self.assertEqual(connector.calls, 0)

    def test_circuit_breaker_stops_repeated_failures(self):
        connector = FakeConnector()
        connector.fail = True
        service = make_service(connector, failure_threshold=1)
        first = asyncio.run(service.call_tool("db__read", {}))
        second = asyncio.run(service.call_tool("db__read", {}))
        self.assertTrue(first.is_error)
        self.assertTrue(second.is_error)
        self.assertEqual(connector.calls, 1)

    def test_real_mcp_server_facade_in_memory(self):
        async def scenario():
            server = PolicyMCPServer(make_service())
            async with Client(server, raise_exceptions=True) as client:
                tools = await client.list_tools()
                self.assertEqual(tools.tools[0].name, "db__read")
                result = await client.call_tool("db__read", {})
                self.assertFalse(result.is_error)
                self.assertEqual(result.content[0].text, "database:read")

        asyncio.run(scenario())


class RegistryTests(unittest.TestCase):
    def test_registry_resolves_prefix(self):
        registry = UpstreamRegistry.from_dict(
            {"one": {"transport": "http", "url": "http://localhost/mcp", "prefix": "alpha"}}
        )
        config, tool = registry.resolve_tool("alpha__search")
        self.assertEqual(config.name, "one")
        self.assertEqual(tool, "search")

    def test_duplicate_prefix_is_rejected(self):
        with self.assertRaises(ValueError):
            UpstreamRegistry.from_dict(
                {
                    "one": {"transport": "http", "url": "http://one/mcp", "prefix": "same"},
                    "two": {"transport": "http", "url": "http://two/mcp", "prefix": "same"},
                }
            )


if __name__ == "__main__":
    unittest.main()
