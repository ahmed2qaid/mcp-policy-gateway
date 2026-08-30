from __future__ import annotations

import argparse
import json
from pathlib import Path

from .audit import JsonlAuditSink
from .policy import Policy, PolicyEngine
from .registry import UpstreamRegistry
from .schema_pin import SchemaPinStore
from .server import PolicyMCPServer
from .service import PolicyGatewayService
from .transport import SDKConnector


def _read_json(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def build_server(config_path: str | Path) -> PolicyMCPServer:
    path = Path(config_path).resolve()
    config = _read_json(path)
    root = path.parent

    if "policy" in config:
        policy_data = config["policy"]
    else:
        policy_file = root / str(config.get("policy_file", "policy.json"))
        policy_data = _read_json(policy_file)
    if not isinstance(policy_data, dict):
        raise ValueError("policy must be an object")

    registry = UpstreamRegistry.from_dict(config.get("upstreams", {}))
    pins = SchemaPinStore.from_dict(config.get("schema_pins", {}))

    audit_sink = None
    if config.get("audit_file"):
        audit_sink = JsonlAuditSink(root / str(config["audit_file"]))

    service = PolicyGatewayService(
        PolicyEngine(Policy.from_dict(policy_data)),
        registry,
        SDKConnector(),
        schema_pins=pins,
        enforce_schema_pins=bool(config.get("enforce_schema_pins", False)),
        auto_pin=bool(config.get("auto_pin", False)),
        audit_sink=audit_sink,
    )
    return PolicyMCPServer(service)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the MCP Policy Gateway")
    parser.add_argument("--config", default="examples/gateway.json", help="Gateway JSON configuration")
    parser.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    server = build_server(args.config)
    if args.transport == "stdio":
        server.run(transport="stdio")
    else:
        server.run(
            transport="streamable-http",
            host=args.host,
            port=args.port,
            stateless_http=True,
            json_response=True,
        )


if __name__ == "__main__":
    main()
