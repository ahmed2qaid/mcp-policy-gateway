from __future__ import annotations

import argparse
import json
from pathlib import Path

from .supply_chain import scan_gateway_config


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan MCP Policy Gateway configuration for supply-chain and deployment risks")
    parser.add_argument("config", nargs="?", default="examples/gateway.json")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--fail-on", choices=["medium", "high", "critical"], default="high")
    args = parser.parse_args()

    path = Path(args.config).resolve()
    config = json.loads(path.read_text(encoding="utf-8"))
    findings = scan_gateway_config(config, root=path.parent)

    if args.format == "json":
        print(json.dumps([finding.__dict__ for finding in findings], indent=2, ensure_ascii=False))
    else:
        if not findings:
            print("PASS no configuration findings")
        for finding in findings:
            print(f"[{finding.severity.upper()}] {finding.code}: {finding.message}")

    rank = {"medium": 1, "high": 2, "critical": 3}
    threshold = rank[args.fail_on]
    return 1 if any(rank.get(finding.severity, 0) >= threshold for finding in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
