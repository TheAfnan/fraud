import base64
import json
import logging
import os
import time
import urllib.request
import urllib.parse
import urllib.error
from typing import Any, Dict, List, Optional
import backend.config as cfg
from backend.security import redact_sensitive_text

logger = logging.getLogger("tigergraph_client")

class TigerGraphClient:
    """
    Production TigerGraph Client for Savanna Cloud and Community Edition.
    Interacts with TigerGraph REST++ and GSQL API endpoints.
    Provides schema deployment, query execution, and health diagnostics.
    """

    def __init__(self, host: str = None, graph: str = None, username: str = None, 
                 password: str = None, secret: str = None, token: str = None):
        self._custom_config = bool(host is not None or graph is not None)
        self.host = (host if host is not None else cfg.TG_HOST).rstrip("/")
        self.graph = graph if graph is not None else cfg.TG_GRAPH
        self.username = username if username is not None else cfg.TG_USERNAME
        self.password = password if password is not None else cfg.TG_PASSWORD
        self.secret = secret if secret is not None else cfg.TG_SECRET
        self.token = token if token is not None else cfg.TG_API_TOKEN
        self._is_live = False
        self._last_error = ""
        self._latency_ms = 0.0

    def refresh_config(self):
        """Reload configuration from backend.config in case .env changed."""
        if not self._custom_config:
            self.host = cfg.TG_HOST.rstrip("/")
            self.graph = cfg.TG_GRAPH
            self.username = cfg.TG_USERNAME
            self.password = cfg.TG_PASSWORD
            self.secret = cfg.TG_SECRET
            self.token = cfg.TG_API_TOKEN

    def _get_auth_headers(self) -> Dict[str, str]:
        headers = {"User-Agent": "HHGOA-Agent/1.0"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        elif self.username and self.password:
            auth_str = f"{self.username}:{self.password}"
            b64_auth = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
            headers["Authorization"] = f"Basic {b64_auth}"
        return headers

    def check_health(self) -> Dict[str, Any]:
        """
        Pings the TigerGraph instance to determine if LIVE mode is operational.
        """
        self.refresh_config()
        if not self.host:
            self._is_live = False
            self._last_error = "TG_HOST not configured"
            return {
                "status": "unconfigured",
                "mode": "CONNECTION_FAILED" if cfg.STRICT_TG_REQUIRED else "LOCAL_FALLBACK",
                "host": "",
                "graph": self.graph,
                "latency_ms": 0.0,
                "error": "TigerGraph host not configured in .env."
            }

        start = time.time()
        try:
            url = f"{self.host}/restpp/echo"
            headers = self._get_auth_headers()
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                elapsed = (time.time() - start) * 1000.0
                self._latency_ms = round(elapsed, 1)
                self._is_live = True
                self._last_error = ""
                return {
                    "status": "connected",
                    "mode": "TIGERGRAPH_LIVE",
                    "host": self.host,
                    "graph": self.graph,
                    "latency_ms": self._latency_ms,
                    "error": None
                }
        except Exception as e:
            self._is_live = False
            safe_err = redact_sensitive_text(str(e))
            self._last_error = safe_err
            return {
                "status": "unreachable",
                "mode": "CONNECTION_FAILED" if cfg.STRICT_TG_REQUIRED else "LOCAL_FALLBACK",
                "host": self.host,
                "graph": self.graph,
                "latency_ms": 0.0,
                "error": f"Failed connecting to TigerGraph at {self.host}: {safe_err}"
            }

    def request_token(self) -> Optional[str]:
        """
        Requests an authentication token from TigerGraph REST++ using TG_SECRET.
        Compatible with TigerGraph 4.x and 3.x.
        """
        if not self.host or not self.secret:
            return None
        
        # TigerGraph 4.x endpoint
        try:
            url_v4 = f"{self.host}/gsql/v1/tokens"
            payload_v4 = json.dumps({"secret": self.secret}).encode('utf-8')
            req_v4 = urllib.request.Request(url_v4, data=payload_v4, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req_v4, timeout=10.0) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                if not data.get("error", False) and data.get("token"):
                    self.token = data.get("token", "")
                    logger.info("Acquired TigerGraph 4.x JWT token via secret.")
                    return self.token
        except Exception as e:
            logger.debug(f"TG 4.x token request failed: {e}. Trying legacy 3.x endpoints.")

        # Legacy 3.x endpoints
        payload = json.dumps({"secret": self.secret, "lifetime": 86400}).encode('utf-8')
        for ep in ["/restpp/requesttoken", "/requesttoken"]:
            url = f"{self.host}{ep}"
            req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=5.0) as resp:
                    data = json.loads(resp.read().decode('utf-8'))
                    if not data.get("error", False):
                        self.token = data.get("results", {}).get("token", "")
                        return self.token
            except Exception:
                continue
        return None

    def execute_gsql(self, gsql_script: str) -> Dict[str, Any]:
        """
        Executes raw GSQL statements against TigerGraph Savanna Cloud / Community Edition.
        Attempts TG 4.x statement API first, then TG 3.x gsqlserver API.
        """
        if not self.host:
            raise ValueError("TG_HOST is not configured. Cannot execute GSQL against live database.")

        # If we don't have token but have secret, request token
        if not self.token and self.secret:
            self.request_token()

        headers = self._get_auth_headers()

        # Method 1: TigerGraph 4.x REST API (/gsql/v1/statements)
        url_v4 = f"{self.host}/gsql/v1/statements"
        req_headers_v4 = dict(headers)
        req_headers_v4["Content-Type"] = "text/plain"
        data_v4 = gsql_script.encode('utf-8')
        
        try:
            req = urllib.request.Request(url_v4, data=data_v4, headers=req_headers_v4)
            with urllib.request.urlopen(req, timeout=120.0) as resp:
                raw = resp.read().decode('utf-8')
                # Ignore harmless 'DROP JOB ... could not be found anywhere' warnings
                cleaned_raw = raw.replace("Semantic Check Fails: These jobs could not be found anywhere", "")
                is_err = "Semantic Check Fails" in cleaned_raw or "Syntax Error" in cleaned_raw or "Failed to" in cleaned_raw
                return {"success": not is_err, "output": raw, "method": "v4_statements"}
        except urllib.error.HTTPError as e:
            err_body = redact_sensitive_text(e.read().decode('utf-8', errors='ignore'))
            # If 404, try legacy 3.x endpoint
            if e.code != 404:
                return {"success": False, "output": err_body, "error": redact_sensitive_text(f"HTTP {e.code}: {err_body}")}
        except Exception as e:
            logger.debug("TG 4.x endpoint failed. Trying legacy 3.x endpoint.")

        # Method 2: TigerGraph 3.x legacy /gsqlserver/gsql/file endpoint
        url_v3 = f"{self.host}/gsqlserver/gsql/file"
        req_headers_v3 = dict(headers)
        req_headers_v3["Content-Type"] = "text/plain"
        data_v3 = gsql_script.encode('utf-8')

        try:
            req = urllib.request.Request(url_v3, data=data_v3, headers=req_headers_v3)
            with urllib.request.urlopen(req, timeout=120.0) as resp:
                raw = resp.read().decode('utf-8')
                cleaned_raw = raw.replace("Semantic Check Fails: These jobs could not be found anywhere", "")
                is_err = "Semantic Check Fails" in cleaned_raw or "Syntax Error" in cleaned_raw or "Failed to" in cleaned_raw
                return {"success": not is_err, "output": raw, "method": "v3_gsqlserver"}
        except urllib.error.HTTPError as e:
            err_body = redact_sensitive_text(e.read().decode('utf-8', errors='ignore'))
            return {"success": False, "output": err_body, "error": redact_sensitive_text(f"HTTP {e.code}: {err_body}")}
        except Exception as e:
            return {"success": False, "output": "", "error": redact_sensitive_text(str(e))}

    def get_schema_metadata(self, graph_name: str = None) -> Dict[str, Any]:
        """
        Retrieves vertex types and edge types from the live graph via REST++ schema API.
        """
        graph = graph_name or self.graph
        if not self.host:
            raise ValueError("TG_HOST not configured.")

        if not self.token and self.secret:
            self.request_token()

        headers = self._get_auth_headers()
        
        # Method 1: TigerGraph 4.x /gsql/v1/schema/graphs/{graph}
        url_v4 = f"{self.host}/gsql/v1/schema/graphs/{graph}"
        try:
            req = urllib.request.Request(url_v4, headers=headers)
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                results = data.get("results", {}) if isinstance(data, dict) else {}
                v_list = results.get("VertexTypes", []) or data.get("vertexTypes", [])
                e_list = results.get("EdgeTypes", []) or data.get("edgeTypes", [])
                
                v_names = []
                for v in v_list:
                    if isinstance(v, dict):
                        v_names.append(v.get("Name") or v.get("name") or "")
                    elif isinstance(v, str):
                        v_names.append(v)
                        
                e_names = []
                for e in e_list:
                    if isinstance(e, dict):
                        e_names.append(e.get("Name") or e.get("name") or "")
                    elif isinstance(e, str):
                        e_names.append(e)

                return {
                    "graph_name": graph,
                    "vertex_types": [v for v in v_names if v],
                    "edge_types": [e for e in e_names if e],
                    "raw": data
                }
        except Exception as e:
            logger.debug(f"TG 4.x schema endpoint failed: {e}. Trying legacy endpoints.")

        # Method 2: Legacy /graph/{graph}/schema
        url = f"{self.host}/graph/{graph}/schema"
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                results = data.get("results", {})
                return {
                    "graph_name": graph,
                    "vertex_types": [v["Name"] if isinstance(v, dict) else v for v in results.get("VertexTypes", [])],
                    "edge_types": [e["Name"] if isinstance(e, dict) else e for e in results.get("EdgeTypes", [])],
                    "raw": results
                }
        except Exception as e2:
            return {
                "graph_name": graph,
                "vertex_types": [],
                "edge_types": [],
                "error": f"Schema retrieval failed: {e2}"
            }

    def run_installed_query(self, query_name: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Executes a pre-installed GSQL query via POST /restpp/query/{graph}/{query_name}
        """
        if not self.is_live():
            raise ConnectionError(f"TigerGraph instance at {self.host} is not reachable. Last error: {self._last_error}")

        if not self.token and self.secret:
            self.request_token()

        headers = self._get_auth_headers()
        headers["Content-Type"] = "application/json"
        data = json.dumps(params or {}).encode('utf-8')

        # Try /restpp/query/{graph}/{query_name} then fallback to /query/...
        urls = [
            f"{self.host}/restpp/query/{self.graph}/{query_name}",
            f"{self.host}/query/{self.graph}/{query_name}"
        ]

        last_exc = None
        for url in urls:
            try:
                req = urllib.request.Request(url, data=data, headers=headers)
                with urllib.request.urlopen(req, timeout=15.0) as resp:
                    return json.loads(resp.read().decode('utf-8'))
            except Exception as e:
                last_exc = e
                continue
        err_msg = redact_sensitive_text(str(last_exc or f"Failed to execute query {query_name}"))
        raise ConnectionError(err_msg)

    def upsert_vertex(self, vertex_type: str, vertex_id: str, attributes: Dict[str, Any]) -> Dict[str, Any]:
        """
        Upserts a vertex into TigerGraph graph via POST /restpp/graph/{graph}/vertices/{vertex_type}
        """
        if not self.is_live():
            raise ConnectionError("TigerGraph is not in live mode.")

        if not self.token and self.secret:
            self.request_token()

        urls = [
            f"{self.host}/restpp/graph/{self.graph}/vertices/{vertex_type}",
            f"{self.host}/graph/{self.graph}/vertices/{vertex_type}"
        ]
        headers = self._get_auth_headers()
        headers["Content-Type"] = "application/json"

        payload = {
            "vertices": {
                vertex_id: attributes
            }
        }
        data = json.dumps(payload).encode('utf-8')
        last_exc = None
        for url in urls:
            try:
                req = urllib.request.Request(url, data=data, headers=headers)
                with urllib.request.urlopen(req, timeout=10.0) as resp:
                    return json.loads(resp.read().decode('utf-8'))
            except Exception as e:
                last_exc = e
                continue
        err_msg = redact_sensitive_text(str(last_exc or f"Failed to upsert vertex {vertex_type}:{vertex_id}"))
        raise ConnectionError(err_msg)

    def is_live(self) -> bool:
        if not self._is_live and self.host:
            self.check_health()
        return self._is_live

# Singleton instance
tigergraph_client = TigerGraphClient()
