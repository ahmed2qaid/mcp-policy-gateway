from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from .service import PolicyGatewayService


class PolicyMCPServer(MCPServer):
    """MCP server facade that exposes policy-filtered upstream tools."""

    def __init__(self, service: PolicyGatewayService) -> None:
        super().__init__("MCP Policy Gateway")
        self.gateway_service = service

    async def list_tools(self):
        return await self.gateway_service.list_tools()

    async def call_tool(self, name: str, arguments: dict, context=None):
        request_id = None
        if context is not None:
            request_context = getattr(context, "request_context", None)
            request_id = getattr(request_context, "request_id", None)
        return await self.gateway_service.call_tool(name, arguments, request_id=request_id)
