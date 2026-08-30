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

- stdio transport bridge
- Streamable HTTP transport
- upstream server registry
- per-server authentication
- request timeouts and circuit breaking
- structured audit sink

## v0.3 — Zero-trust controls

- per-agent identity
- signed approval tokens
- rate limiting
- argument-level policy conditions
- egress/domain allowlists
- secret and PII redaction
- prompt-injection risk signals

## v0.4 — Supply-chain protection

- schema registry
- signed schema pins
- tool-name shadowing detection
- server fingerprinting
- policy bundles
- CI security scan for MCP configurations

## v1.0

- production proxy transports
- policy hot reload
- external approval API
- OpenTelemetry integration
- admin/audit dashboard
- compatibility tests with major MCP clients and servers
- documented threat model and security review
