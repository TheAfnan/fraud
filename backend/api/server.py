"""
Lightweight REST API Server and Static File Server for Analyst Console.
Built with standard library http.server.ThreadingHTTPServer.
Exposes endpoints for case investigations, live graph visualization data, and health diagnostics.
"""

import os
import sys
import json
import time
import urllib.parse
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, List, Optional
import logging

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.tigergraph.gateway import graph_gateway
from backend.agent.investigator import investigation_agent
from backend.security import redact_sensitive_text

logger = logging.getLogger("fraud_api_server")
CASES_DIR = PROJECT_ROOT / "cases"
FRONTEND_DIR = PROJECT_ROOT / "frontend"
DATA_DIR = PROJECT_ROOT / "data"

class FraudAnalystRequestHandler(BaseHTTPRequestHandler):
    """
    Handles REST API requests and serves frontend static assets.
    """

    def send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()

    def _send_json(self, data: Any, status: int = 200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_cors_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, message: str, status: int = 400):
        self._send_json({"error": message, "status": status}, status=status)

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path.rstrip("/")
        if not path:
            path = "/"

        # API: Health
        if path == "/api/health":
            engine_status = graph_gateway.get_engine_status()
            coverage = graph_gateway.get_data_coverage_summary()
            self._send_json({
                "status": "healthy",
                "tigergraph": engine_status,
                "coverage": coverage,
                "policy_version": "1.0",
                "mcp_implementation": "custom_mcp_compatible_server",
                "llm_runtime": "unavailable_in_environment_deterministic_policy_reasoning_used",
                "mcp_tools_count": 16,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            })
            return

        # API: List all cases
        if path == "/api/cases":
            cases_list = []
            if CASES_DIR.exists():
                for c_file in sorted(CASES_DIR.glob("*.json")):
                    try:
                        with open(c_file, "r", encoding="utf-8") as f:
                            c_data = json.load(f)
                            c_case = c_data.get("case", {})
                            cases_list.append({
                                "case_id": c_data.get("case_id"),
                                "verdict": c_case.get("verdict"),
                                "status": c_case.get("status"),
                                "pattern": c_case.get("pattern"),
                                "fraud_probability": c_case.get("fraud_probability"),
                                "exposure_usd": c_case.get("exposure_usd"),
                                "sar_filed": c_data.get("sar", {}).get("file", False),
                                "written_to_graph": c_case.get("written_to_graph", False),
                                "tool_calls": c_data.get("tool_calls", 0),
                                "latency_s": c_data.get("latency_s", 0.0)
                            })
                    except Exception as e:
                        logger.warning(f"Error reading {c_file}: {e}")
            self._send_json({"cases": cases_list, "total": len(cases_list)})
            return

        # API: Specific case details /api/cases/{case_id}
        if path.startswith("/api/cases/"):
            case_id = path.split("/api/cases/")[1]
            case_file = CASES_DIR / f"{case_id}.json"
            if case_file.exists():
                with open(case_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._send_json(data)
                return
            else:
                self._send_error(f"Case {case_id} not found", 404)
                return

        # API: Graph visualization elements /api/investigations/{case_id}/graph
        if path.startswith("/api/investigations/") and path.endswith("/graph"):
            parts = path.split("/")
            case_id = parts[3]
            graph_data = self._generate_cytoscape_elements(case_id)
            self._send_json(graph_data)
            return

        # API: Timeline /api/cases/{case_id}/timeline
        if path.startswith("/api/cases/") and path.endswith("/timeline"):
            case_id = path.split("/")[3]
            card_id = ""
            import csv
            with open(DATA_DIR / "case_pack.csv", "r", encoding="utf-8") as f:
                for r in csv.DictReader(f):
                    if r["case_id"] == case_id:
                        card_id = r["card_id"]
                        break
            if card_id:
                w_res = graph_gateway.card_window(card_id, 168)
                txns = w_res.get("transactions", [])
                txns.sort(key=lambda t: t.get("ts", ""))
                self._send_json({"case_id": case_id, "card_id": card_id, "timeline": txns[-20:]})
                return
            else:
                self._send_error("Case not found", 404)
                return

        # Static Frontend Assets
        target_file = None
        if path == "/":
            target_file = FRONTEND_DIR / "index.html"
        else:
            rel_path = path.lstrip("/")
            target_file = FRONTEND_DIR / rel_path

        if target_file and target_file.is_file():
            self._serve_file(target_file)
            return

        self._send_error("Not Found", 404)

    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path.rstrip("/")

        # MCP Standard JSON-RPC 2.0 Endpoint
        if path == "/mcp":
            content_length = int(self.headers.get("Content-Length", 0))
            body_bytes = self.rfile.read(content_length)
            try:
                rpc_req = json.loads(body_bytes.decode("utf-8"))
                from backend.mcp.server import mcp_server
                rpc_resp = mcp_server.handle_json_rpc(rpc_req)
                self._send_json(rpc_resp)
            except Exception as e:
                self._send_error(f"Malformed JSON-RPC: {e}", 400)
            return

        # API: Re-run investigation /api/investigations/{case_id}/run
        if path.startswith("/api/investigations/") and path.endswith("/run"):
            case_id = path.split("/")[3]
            # Find case in case pack
            case_pack_file = DATA_DIR / "case_pack.csv"
            case_info = None
            if case_pack_file.exists():
                import csv
                with open(case_pack_file, "r", encoding="utf-8") as f:
                    for r in csv.DictReader(f):
                        if r["case_id"] == case_id:
                            case_info = r
                            break
            if not case_info:
                self._send_error(f"Case {case_id} not in case pack", 404)
                return

            res = investigation_agent.investigate_case(case_info)
            # Save updated
            out_file = CASES_DIR / f"{case_id}.json"
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(res, f, indent=2)
            self._send_json(res)
            return

        self._send_error("Endpoint not supported", 404)

    def _generate_cytoscape_elements(self, case_id: str) -> Dict[str, Any]:
        """
        Builds graph elements for Cytoscape.js visualization.
        """
        nodes = []
        edges = []

        case_file = CASES_DIR / f"{case_id}.json"
        if not case_file.exists():
            return {"elements": []}

        with open(case_file, "r", encoding="utf-8") as f:
            case_record = json.load(f)

        c = case_record.get("case", {})
        flagged_txn_id = ""
        # Find flagged txn from evidence
        for ev in c.get("evidence", []):
            if ev.get("ref") == "trigger:model_risk_score" or ev.get("ref") == "trigger:customer_report":
                for eid in ev.get("entity_ids", []):
                    if eid.isdigit():
                        flagged_txn_id = eid
                        break

        # Read case pack info
        card_id = ""
        customer_id = ""
        import csv
        with open(DATA_DIR / "case_pack.csv", "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if row["case_id"] == case_id:
                    card_id = row["card_id"]
                    customer_id = row["customer_id"]
                    flagged_txn_id = row["flagged_txn_id"]
                    break

        # Customer Node
        if customer_id:
            nodes.append({
                "data": {"id": customer_id, "label": f"Customer\n{customer_id}", "type": "customer", "color": "#3B82F6"}
            })

        # Card Node
        if card_id:
            nodes.append({
                "data": {"id": card_id, "label": f"Card\n{card_id}", "type": "card", "color": "#8B5CF6"}
            })
            if customer_id:
                edges.append({
                    "data": {"id": f"e_{customer_id}_{card_id}", "source": customer_id, "target": card_id, "label": "OWNS"}
                })

        # Flagged Transaction Node
        if flagged_txn_id:
            is_fraud = c.get("verdict") == "fraud"
            nodes.append({
                "data": {
                    "id": flagged_txn_id,
                    "label": f"Flagged Txn\n#{flagged_txn_id}",
                    "type": "transaction",
                    "color": "#EF4444" if is_fraud else "#10B981",
                    "highlight": True
                }
            })
            if card_id:
                edges.append({
                    "data": {"id": f"e_{card_id}_{flagged_txn_id}", "source": card_id, "target": flagged_txn_id, "label": "MADE"}
                })

        # Connected Devices
        for dev in c.get("connected_device_profiles", []):
            dev_id = f"dev_{hash(dev) % 10000}"
            short_dev = dev.split("|")[0].strip() if "|" in dev else dev[:25]
            nodes.append({
                "data": {"id": dev_id, "label": f"Device\n{short_dev}", "type": "device", "color": "#F59E0B"}
            })
            if flagged_txn_id:
                edges.append({
                    "data": {"id": f"e_{flagged_txn_id}_{dev_id}", "source": flagged_txn_id, "target": dev_id, "label": "FROM_DEVICE"}
                })

        # Connected Cards
        for cc_id in c.get("connected_card_ids", [])[:5]:
            nodes.append({
                "data": {"id": cc_id, "label": f"Linked Card\n{cc_id}", "type": "card", "color": "#EC4899"}
            })
            # Link to device if present
            if c.get("connected_device_profiles"):
                dev_id = f"dev_{hash(c.get('connected_device_profiles')[0]) % 10000}"
                edges.append({
                    "data": {"id": f"e_{cc_id}_{dev_id}", "source": cc_id, "target": dev_id, "label": "USED_DEVICE"}
                })

        # Prior Closed Cases
        for sc_id in c.get("similar_prior_cases", []):
            nodes.append({
                "data": {"id": sc_id, "label": f"Precedent Case\n{sc_id}", "type": "case", "color": "#6366F1"}
            })
            if card_id:
                edges.append({
                    "data": {"id": f"e_{card_id}_{sc_id}", "source": card_id, "target": sc_id, "label": "SIMILAR_TO"}
                })

        return {"elements": {"nodes": nodes, "edges": edges}}

    def _serve_file(self, file_path: Path):
        ext = file_path.suffix.lower()
        content_types = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".json": "application/json; charset=utf-8",
            ".png": "image/png",
            ".svg": "image/svg+xml"
        }
        content_type = content_types.get(ext, "application/octet-stream")
        with open(file_path, "rb") as f:
            content = f.read()
        self.send_response(200)
        self.send_cors_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

def start_server(port: int = 8000):
    server_address = ("127.0.0.1", port)
    httpd = ThreadingHTTPServer(server_address, FraudAnalystRequestHandler)
    logger.info(f"TigerGraph Fraud Analyst Console server running on http://127.0.0.1:{port}")
    httpd.serve_forever()

if __name__ == "__main__":
    start_server(8000)
