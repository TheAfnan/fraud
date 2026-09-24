"""
Model Context Protocol (MCP) Client.
Allows the Autonomous Agent to discover and invoke tools using the authentic MCP protocol specification.
"""

from typing import Any, Dict, List, Optional
import json
import logging
from backend.mcp.server import mcp_server

logger = logging.getLogger("mcp_client")

class TigerGraphMCPClient:
    """
    Standard MCP Client for communicating with the TigerGraph MCP Server.
    """

    def __init__(self, server=None):
        self.server = server or mcp_server
        self._request_counter = 0

    def _next_id(self) -> int:
        self._request_counter += 1
        return self._request_counter

    def initialize(self) -> Dict[str, Any]:
        """Performs standard MCP initialization."""
        req = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "initialize",
            "params": {
                "clientInfo": {"name": "fraud-investigation-agent", "version": "1.0.0"}
            }
        }
        resp = self.server.handle_json_rpc(req)
        return resp.get("result", {})

    def list_tools(self) -> List[Dict[str, Any]]:
        """Queries available tools via tools/list."""
        req = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "tools/list",
            "params": {}
        }
        resp = self.server.handle_json_rpc(req)
        return resp.get("result", {}).get("tools", [])

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes an MCP tool via tools/call.
        Returns the structured result payload.
        """
        req = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments
            }
        }
        resp = self.server.handle_json_rpc(req)
        if "error" in resp:
            raise RuntimeError(f"MCP Protocol Error ({resp['error'].get('code')}): {resp['error'].get('message')}")

        result_payload = resp.get("result", {})
        content_items = result_payload.get("content", [])
        if content_items and content_items[0].get("type") == "text":
            try:
                parsed = json.loads(content_items[0]["text"])
                if parsed.get("error"):
                    logger.warning(f"MCP Tool '{name}' returned application error: {parsed.get('message')}")
                return parsed.get("result", parsed)
            except Exception:
                return {"raw_text": content_items[0]["text"]}
        return result_payload

mcp_client = TigerGraphMCPClient()
