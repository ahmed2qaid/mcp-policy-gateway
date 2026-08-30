import unittest

from mcp_policy_gateway import Policy, PolicyEngine, PolicyGateway, SchemaPinStore


class GatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = Policy.from_dict(
            {
                "default": "deny",
                "rules": [
                    {"id": "read", "tool": "db.read*", "effect": "allow", "risk": "low"},
                    {"id": "delete", "tool": "db.delete*", "effect": "approval", "risk": "high"},
                    {"id": "drop", "tool": "db.drop*", "effect": "deny", "risk": "critical"},
                ],
            }
        )
        self.events = []
        self.gateway = PolicyGateway(PolicyEngine(self.policy), audit_sink=self.events.append)

    @staticmethod
    def upstream(message: dict) -> dict:
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": {"forwarded": True}}

    def call(self, tool: str) -> dict:
        return self.gateway.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": tool, "arguments": {}},
            },
            self.upstream,
        )

    def test_allowed_call_reaches_upstream(self) -> None:
        response = self.call("db.read_customer")
        self.assertTrue(response["result"]["forwarded"])
        self.assertEqual(self.events[-1].effect, "allow")

    def test_approval_call_is_held(self) -> None:
        response = self.call("db.delete_customer")
        self.assertEqual(response["error"]["code"], -32002)
        self.assertTrue(response["error"]["data"]["approval_required"])
        self.assertEqual(self.events[-1].risk, "high")

    def test_denied_call_never_reaches_upstream(self) -> None:
        response = self.call("db.drop_table")
        self.assertEqual(response["error"]["code"], -32001)
        self.assertEqual(self.events[-1].risk, "critical")

    def test_schema_pin_detects_drift(self) -> None:
        pins = SchemaPinStore()
        original = {"type": "object", "properties": {"id": {"type": "string"}}}
        changed = {"type": "object", "properties": {"id": {"type": "string"}, "force": {"type": "boolean"}}}
        pins.pin("db.delete_customer", original)

        self.assertTrue(pins.verify("db.delete_customer", original).trusted)
        self.assertFalse(pins.verify("db.delete_customer", changed).trusted)


if __name__ == "__main__":
    unittest.main()
