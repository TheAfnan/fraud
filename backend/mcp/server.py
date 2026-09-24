"""
Official Model Context Protocol (MCP) JSON-RPC 2.0 Server for TigerGraph.
Provides strict MCP protocol compliance with tools/list, tools/call, initialize, and ping methods.
Operates over stdio for standard MCP hosts (e.g., Claude Desktop, Cursor, Agent host) or via HTTP transport.
"""

import sys
import json
import logging
from typing import Any, Dict, List, Optional
from backend.mcp.tools import mcp_registry
from backend.security import redact_sensitive_text

logger = logging.getLogger("tigergraph_mcp_server")

class TigerGraphMCPServer:
    """
    Standard Model Context Protocol (MCP) Server implementing JSON-RPC 2.0.
    """

    PROTOCOL_VERSION = "2024-11-05"
    SERVER_NAME = "tigergraph-fraud-mcp"
    SERVER_VERSION = "1.0.0"

    def __init__(self, registry=None):
        self.registry = registry or mcp_registry

    def handle_json_rpc(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes an incoming JSON-RPC 2.0 request and returns an MCP response.
        """
        req_id = request_data.get("id")
        method = request_data.get("method", "")
        params = request_data.get("params", {})

        if request_data.get("jsonrpc") != "2.0":
            return self._make_error(req_id, -32600, "Invalid Request: jsonrpc must be '2.0'")

        try:
            if method == "initialize":
                return self._handle_initialize(req_id, params)
            elif method == "ping":
                return self._make_response(req_id, {})
            elif method == "tools/list":
                return self._handle_tools_list(req_id)
            elif method == "tools/call":
                return self._handle_tools_call(req_id, params)
            else:
                return self._make_error(req_id, -32601, f"Method not found: {method}")
        except Exception as e:
            safe_err = redact_sensitive_text(str(e))
            logger.error(f"Internal MCP error handling method '{method}': {safe_err}")
            return self._make_error(req_id, -32603, f"Internal error: {safe_err}")

    def _handle_initialize(self, req_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        return self._make_response(req_id, {
            "protocolVersion": self.PROTOCOL_VERSION,
            "capabilities": {
                "tools": {
                    "listChanged": False
                }
            },
            "serverInfo": {
                "name": self.SERVER_NAME,
                "version": self.SERVER_VERSION
            }
        })

    def _handle_tools_list(self, req_id: Any) -> Dict[str, Any]:
        tools_list = self.registry.list_tools()
        return self._make_response(req_id, {
            "tools": tools_list
        })

    def _handle_tools_call(self, req_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        if not tool_name:
            return self._make_error(req_id, -32602, "Missing parameter 'name' in tools/call")

        execution_result = self.registry.execute_tool(tool_name, arguments)
        
        is_error = execution_result.get("error", False)
        content_text = json.dumps(execution_result, indent=2)

        return self._make_response(req_id, {
            "content": [
                {
                    "type": "text",
                    "text": content_text
                }
            ],
            "isError": is_error
        })

    def _make_response(self, req_id: Any, result: Any) -> Dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": result
        }

    def _make_error(self, req_id: Any, code: int, message: str) -> Dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": code,
                "message": message
            }
        }

    def run_stdio(self):
        """
        Runs the MCP server over standard input/output streams.
        """
        logger.info(f"{self.SERVER_NAME} v{self.SERVER_VERSION} listening on stdio...")
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
                response = self.handle_json_rpc(request)
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
            except Exception as e:
                err_resp = self._make_error(None, -32700, f"Parse error: {e}")
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()

mcp_server = TigerGraphMCPServer()

if __name__ == "__main__":
    mcp_server.run_stdio()
