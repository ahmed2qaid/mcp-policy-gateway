# Execution Roadmap

## v0.1 — Policy enforcement core

- [x] policy-as-code model
- [x] wildcard tool rules
- [x] allow/deny/approval decisions
- [x] MCP `tools/call` interception
- [x] audit events
- [x] tool schema pinning and drift detection
- [x] tests and CI

## v0.2 — Network gateway

- [x] real MCP server facade using the official MCP Python SDK v2
- [x] stdio and Streamable HTTP client-facing transports
- [x] stdio and Streamable HTTP upstream transports
- [x] upstream registry and collision-safe tool namespaces
- [x] environment-backed upstream authentication
- [x] timeouts, circuit breaking, JSONL audit
- [x] schema-pin enforcement and MCP integration tests

## v0.3 — Zero-trust controls

- [x] per-agent identity model
- [x] signed, short-lived approval tokens bound to tool arguments
- [x] approval resume flow in the policy service
- [x] per-agent/per-tool sliding-window rate limiting
- [x] identity, role, and argument-level policy conditions
- [x] egress/domain allowlists
- [x] secret and PII redaction helpers
- [x] prompt-injection risk signals
- [x] persistent upstream sessions with opt-out and automatic reconnect after transport failure

Exit criteria: high-risk tool calls can be constrained by agent identity, arguments, rate limits and egress policy, then resumed only with a request-bound signed approval. Upstream MCP sessions can also be reused safely without paying a fresh initialization handshake for every tool operation.

## v0.4 — Supply-chain protection

- [x] persistent file-backed schema registry
- [x] signed schema/fingerprint manifests with tamper verification
- [x] tool-name shadowing and namespace-impersonation detection
- [x] deterministic upstream server fingerprinting from transport + tool schemas
- [x] validated policy bundle model
- [x] configuration security scanner with severity thresholds
- [x] CI security gate for MCP gateway configuration

Exit criteria: changes to MCP tool schemas, upstream identity, tool naming, and gateway configuration can be reviewed and blocked before deployment instead of being trusted implicitly at runtime.

## v1.0

- policy hot reload
- external approval API
- OpenTelemetry integration
- admin/audit dashboard
- compatibility tests with major MCP clients and servers
- deployment hardening and documented threat model
- independent security review checklist
