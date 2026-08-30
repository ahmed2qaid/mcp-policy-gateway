# MCP Policy Gateway

A zero-trust policy enforcement gateway that sits between AI agents/MCP clients and real MCP servers.

```text
MCP Client / AI Agent
        ↓
Identity + Rate Limit + Policy + Approval + Egress Guard
        ↓
MCP Policy Gateway
        ↓
Schema Pin + Circuit Breaker + Audit
        ↓
 one or many MCP upstream servers
```

## Why it exists

MCP makes tool access easy; production systems also need to answer **who may call a tool, with which arguments, how often, to which destinations, and when a human must approve the action**. MCP Policy Gateway keeps those controls outside the agent prompt and applies them before the upstream tool executes.

Tools are namespaced at the gateway boundary to prevent collisions:

```text
local__filesystem_read
crm__customer_lookup
billing__refund_payment
```

## v0.3 — zero-trust controls

- real MCP stdio and Streamable HTTP gateway from v0.2
- per-agent identity (`agent_id`, tenant, roles)
- identity/role-aware policy rules
- argument-level `argument_equals` policy conditions
- short-lived HMAC approval tokens bound to agent + tool + exact arguments
- approval resume without weakening the original rule
- per-agent/per-tool sliding-window rate limits
- outbound URL/domain allowlists
- prompt-injection signal detection before high-risk tool execution
- secret/email redaction helpers for logs and operator surfaces
- upstream circuit breakers and request timeouts
- schema pinning and drift enforcement
- structured JSONL audit
- tests and CI

## Policy example

```json
{
  "default": "deny",
  "rules": [
    {
      "id": "finance-refund-usd",
      "tool": "billing__refund*",
      "effect": "approval",
      "risk": "high",
      "roles_any": ["finance"],
      "argument_equals": {"currency": "USD"}
    },
    {
      "id": "block-delete",
      "tool": "billing__delete*",
      "effect": "deny",
      "risk": "critical"
    }
  ]
}
```

## Signed approval flow

```python
identity = AgentIdentity("agent-42", tenant="acme", roles=("finance",))
args = {"invoice_id": "INV-7", "amount": 50, "currency": "USD"}

first = await service.call_tool("billing__refund", args, identity=identity)
# -> approval_required

token = signer.issue(tool="billing__refund", arguments=args, identity=identity)
result = await service.call_tool(
    "billing__refund",
    args,
    identity=identity,
    approval_token=token,
)
```

Changing the amount, tool, agent or tenant invalidates the token.

## Install

```bash
pip install -e .
```

The gateway targets the stable MCP Python SDK v2 line (`mcp>=2.1,<3`).

## Run over stdio

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

Clients connect to `http://127.0.0.1:8000/mcp`.

## Security boundary

v0.3 provides a practical policy layer, not a claim of complete isolation. Persistent identity extraction from every client transport, external approval APIs, signed schema registries, policy hot reload, OpenTelemetry, deployment hardening and a formal threat model remain roadmap items.

See [ROADMAP.md](ROADMAP.md).

## License

MIT.
