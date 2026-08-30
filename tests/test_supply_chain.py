from __future__ import annotations

import os
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from mcp_policy_gateway.registry import UpstreamRegistry
from mcp_policy_gateway.schema_pin import SchemaPinStore
from mcp_policy_gateway.supply_chain import (
    SignedSchemaManifest,
    detect_tool_shadowing,
    scan_gateway_config,
    server_fingerprint,
)


@dataclass
class Tool:
    name: str
    input_schema: dict


class SupplyChainTests(unittest.TestCase):
    def test_signed_schema_manifest_detects_tampering(self):
        pins = SchemaPinStore()
        pins.pin("billing__refund", {"type": "object", "properties": {"amount": {"type": "number"}}})
        manifest = SignedSchemaManifest.issue(
            pins=pins,
            fingerprints={"billing": "a" * 64},
            secret=b"test-secret",
        )
        self.assertTrue(manifest.verify(b"test-secret"))
        tampered = SignedSchemaManifest.from_dict({**manifest.to_dict(), "fingerprints": {"billing": "b" * 64}})
        self.assertFalse(tampered.verify(b"test-secret"))

    def test_server_fingerprint_changes_with_tool_schema(self):
        registry = UpstreamRegistry.from_dict(
            {"billing": {"transport": "http", "url": "https://mcp.example.com", "prefix": "billing"}}
        )
        config = next(iter(registry))
        a = server_fingerprint(config, [Tool("refund", {"type": "object"})])
        b = server_fingerprint(
            config,
            [Tool("refund", {"type": "object", "required": ["amount"]})],
        )
        self.assertNotEqual(a, b)

    def test_shadowing_detects_same_raw_tool_across_servers(self):
        registry = UpstreamRegistry.from_dict(
            {
                "billing": {"transport": "http", "url": "https://billing.example.com", "prefix": "billing"},
                "crm": {"transport": "http", "url": "https://crm.example.com", "prefix": "crm"},
            }
        )
        issues = detect_tool_shadowing(
            registry,
            {
                "billing": [Tool("delete", {})],
                "crm": [Tool("delete", {})],
            },
        )
        self.assertTrue(any("multiple upstreams" in issue for issue in issues))

    def test_config_scan_flags_remote_http_and_inline_secret(self):
        config = {
            "policy": {"default": "allow", "rules": []},
            "upstreams": {
                "crm": {
                    "transport": "http",
                    "url": "http://crm.example.com/mcp",
                    "prefix": "crm",
                    "env": {"API_TOKEN": "literal-secret"},
                }
            },
        }
        findings = scan_gateway_config(config)
        codes = {finding.code for finding in findings}
        self.assertIn("policy.default_allow", codes)
        self.assertIn("upstream.insecure_http", codes)
        self.assertIn("upstream.inline_secret", codes)
        self.assertIn("schema.unpinned", codes)


if __name__ == "__main__":
    unittest.main()
