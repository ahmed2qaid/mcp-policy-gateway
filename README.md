# MCP Policy Gateway

A zero-trust policy enforcement gateway that sits between AI agents/MCP clients and real MCP servers.

```text
MCP Client / AI Agent
        ↓
MCP Policy Gateway
        ↓
Policy + schema pin + circuit breaker + audit
        ↓
 one or many MCP upstream servers
```

## What makes it different

The gateway is policy-first rather than vendor-first. Upstreams can be local stdio servers or remote Streamable HTTP servers, while the same policy engine decides whether a tool call is allowed, denied, or held for approval.

Tools are namespaced at the gateway boundary to prevent collisions:

```text
local__filesystem_read
crm__customer_lookup
billing__refund_payment
```

## v0.2 — real MCP gateway

- real MCP server facade built on the official MCP Python SDK v2
- stdio client-facing transport
- Streamable HTTP client-facing transport
- stdio upstream servers
- Streamable HTTP upstream servers
- upstream registry and collision-safe tool namespaces
- bearer/header authentication sourced from environment variables
- request timeouts
- per-upstream circuit breakers
- structured append-only JSONL audit log
- policy `allow`, `deny`, and `approval` decisions before forwarding
- schema pin verification and optional enforcement
- in-memory MCP protocol integration test
- CI

## Install

```bash
pip install -e .
```

The project targets the stable MCP Python SDK v2 line (`mcp>=2.1,<3`).

## Configure

Copy `examples/gateway.json` and point its upstreams at your MCP servers. Secrets are referenced by environment-variable name rather than stored directly in the config.

```json
{
  "policy_file": "policy.json",
  "audit_file": "audit.jsonl",
  "upstreams": {
    "billing": {
      "transport": "http",
      "url": "https://billing.internal/mcp",
      "prefix": "billing",
      "bearer_token_env": "BILLING_MCP_TOKEN"
    }
  }
}
```

Policy example:

```json
{
  "default": "deny",
  "rules": [
    {"id": "read", "tool": "billing__invoice_read*", "effect": "allow", "risk": "low"},
    {"id": "refund", "tool": "billing__refund*", "effect": "approval", "risk": "high"},
    {"id": "delete", "tool": "billing__delete*", "effect": "deny", "risk": "critical"}
  ]
}
```

## Run over stdio

Useful for desktop/IDE hosts that launch an MCP server as a subprocess:

```bash
mcp-policy-gateway --config examples/gateway.json --transport stdio
```

## Run over Streamable HTTP

```bash
mcp-policy-gateway \
  --config examples/gateway.json \
  --transport streamable-http \
  --host 127.0.0.1 \
  --port 8000
```

Clients connect to:

```text
http://127.0.0.1:8000/mcp
```

The HTTP server is stateless and uses JSON responses, matching the current MCP SDK deployment recommendation for scalable production gateways.

## Current security boundary

v0.2 enforces tool-level policy before forwarding and can detect pinned tool-schema drift. It does **not** yet claim full production zero-trust: per-agent identity, signed approvals, argument-level policy, rate limits, egress rules, PII redaction, and prompt-injection signals are scheduled next.

See [ROADMAP.md](ROADMAP.md).

## License

MIT.
