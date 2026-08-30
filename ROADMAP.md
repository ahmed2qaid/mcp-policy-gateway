# Execution Roadmap

## v0.1 — Policy enforcement core

- [x] policy-as-code model
- [x] wildcard tool rules
- [x] allow/deny/approval decisions
- [x] MCP `tools/call` interception
- [x] audit events
- [x] tool schema pinning and drift detection
- [x] tests and CI

Exit criteria: a tool call can be blocked or held for approval before reaching an upstream MCP server.

## v0.2 — Network gateway

- [x] real MCP server facade using the official MCP Python SDK v2
- [x] stdio client-facing transport
- [x] Streamable HTTP client-facing transport
- [x] stdio upstream transport
- [x] Streamable HTTP upstream transport
- [x] upstream server registry and tool namespacing
- [x] per-server bearer/custom-header authentication sourced from environment variables
- [x] request timeouts
- [x] per-upstream circuit breaking
- [x] structured JSONL audit sink
- [x] optional schema-pin enforcement at tool discovery
- [x] MCP protocol integration test using an in-memory client

Exit criteria: a standard MCP client can connect to the gateway, discover namespaced tools from one or more upstreams, and invoke only policy-approved tools.

## v0.3 — Zero-trust controls

- per-agent identity
- signed approval tokens and approval resume flow
- rate limiting
- argument-level policy conditions
- egress/domain allowlists
- secret and PII redaction
- prompt-injection risk signals
- persistent HTTP/stdio upstream sessions where appropriate

## v0.4 — Supply-chain protection

- persistent schema registry
- signed schema pins
- tool-name shadowing detection
- server fingerprinting
- policy bundles
- CI security scan for MCP configurations

## v1.0

- policy hot reload
- external approval API
- OpenTelemetry integration
- admin/audit dashboard
- compatibility tests with major MCP clients and servers
- deployment hardening and documented threat model
- independent security review checklist
