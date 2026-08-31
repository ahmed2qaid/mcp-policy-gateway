# Demo Integration Contract

This repository remains an independent security product. The end-to-end demo consumes it as the zero-trust MCP boundary; demo-specific orchestration does not live here.

## Role in `ai-automation-infra-demo`

```text
AI agent / orchestration
        ↓ MCP
MCP Policy Gateway
        ↓ policy + identity + approval + supply-chain checks
Demo MCP servers
```

## Demo responsibilities

- expose namespaced MCP tools from one or more upstream demo servers
- deny explicitly forbidden tools
- require signed approval for high-risk side effects
- enforce agent identity, roles, argument conditions and rate limits
- verify schema pins/server fingerprints before forwarding calls
- emit structured audit records for the demo timeline

## Stable integration surface

The demo treats the gateway as an external process and connects through the MCP protocol. It must not import internal gateway modules to bypass policy enforcement.

The demo configuration should be mounted at runtime and secrets must arrive through environment variables. Production-like examples should use Streamable HTTP for service-to-service traffic; stdio remains useful for local developer demonstrations.

## End-to-end scenario

The reference scenario uses a refund-style tool as the high-risk action:

1. an agent requests a refund through MCP;
2. the gateway identifies the tool as high risk;
3. the first call returns an approval requirement;
4. the durable execution pauses;
5. a human approval token is issued;
6. the same request resumes with the request-bound token;
7. the gateway forwards the call and audits the decision.

## Boundary rule

The demo may configure and run this project, but security logic stays in `mcp-policy-gateway`. Any feature needed by the demo that belongs to policy enforcement must be implemented here first, then consumed by the demo.
