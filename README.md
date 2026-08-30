# MCP Policy Gateway

A zero-trust policy enforcement layer for MCP tool calls.

```text
MCP Client / AI Agent
        ↓
MCP Policy Gateway
        ↓
Policy decision
  allow / deny / approval
        ↓
MCP Server
```

The project is intentionally policy-first: transport adapters can change, while the security decision model remains stable and testable.

## v0.1

- ordered policy-as-code rules
- wildcard tool matching
- `allow`, `deny`, and `approval` decisions
- interception of MCP JSON-RPC `tools/call`
- audit events for every tool decision
- tool schema pinning with SHA-256 drift detection
- zero-dependency Python core
- tests and CI

## Example policy

```json
{
  "default": "deny",
  "rules": [
    {"id": "read-only", "tool": "database.read*", "effect": "allow", "risk": "low"},
    {"id": "delete-review", "tool": "database.delete*", "effect": "approval", "risk": "high"},
    {"id": "block-drop", "tool": "database.drop*", "effect": "deny", "risk": "critical"}
  ]
}
```

## Security direction

Future versions add authentication, per-agent identity, egress policy, prompt-injection signals, secret/PII redaction, signed policies, rate limits, approval tokens, and network transports.

See [ROADMAP.md](ROADMAP.md).

## Status

v0.1 foundation.

## License

MIT.