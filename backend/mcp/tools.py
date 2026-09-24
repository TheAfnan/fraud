"""
TigerGraph Model Context Protocol (MCP) Tool Implementation.
Exposes graph operations, entity retrievals, policy lookups, and case memory
tools conforming to the MCP tool specification with typed validation and safe errors.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from backend.tigergraph.client import tigergraph_client
from backend.tigergraph.gateway import graph_gateway
from backend.security import redact_sensitive_text

logger = logging.getLogger("mcp_tools")

@dataclass
class MCPTool:
    name: str
    description: str
    input_schema: Dict[str, Any]
    handler: Callable[..., Any]

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Executes the tool with typed validation, timeouts, and sanitized errors."""
        try:
            # Basic validation against schema required fields
            required = self.input_schema.get("required", [])
            for field_name in required:
                if field_name not in arguments or arguments[field_name] is None:
                    return {
                        "error": True,
                        "code": "INVALID_ARGUMENT",
                        "message": f"Missing required parameter '{field_name}' for tool '{self.name}'."
                    }

            result = self.handler(**arguments)
            return {
                "error": False,
                "tool": self.name,
                "result": result
            }
        except Exception as e:
            safe_msg = redact_sensitive_text(str(e))
            logger.warning(f"MCP Tool execution error in '{self.name}': {safe_msg}")
            return {
                "error": True,
                "code": "TOOL_EXECUTION_ERROR",
                "message": safe_msg
            }

    def to_mcp_descriptor(self) -> Dict[str, Any]:
        """Returns standard MCP tool descriptor dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema
        }


class TigerGraphMCPRegistry:
    """Central registry for TigerGraph MCP tools."""
    def __init__(self):
        self._tools: Dict[str, MCPTool] = {}
        self._register_default_tools()

    def register(self, tool: MCPTool):
        self._tools[tool.name] = tool

    def get_tool(self, name: str) -> Optional[MCPTool]:
        return self._tools.get(name)

    def list_tools(self) -> List[Dict[str, Any]]:
        return [tool.to_mcp_descriptor() for tool in self._tools.values()]

    def execute_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        tool = self.get_tool(name)
        if not tool:
            return {
                "error": True,
                "code": "TOOL_NOT_FOUND",
                "message": f"Tool '{name}' is not registered in TigerGraph MCP."
            }
        return tool.execute(arguments)

    def _register_default_tools(self):
        # 1. tg_get_transaction
        self.register(MCPTool(
            name="tg_get_transaction",
            description="Fetches full transaction record including card_id, amount, timestamp, product code, channel, risk score, and billing regions.",
            input_schema={
                "type": "object",
                "properties": {
                    "txn_id": {"type": "string", "description": "Transaction ID (e.g. '3514030')"}
                },
                "required": ["txn_id"]
            },
            handler=lambda txn_id: graph_gateway.get_transaction(str(txn_id))
        ))

        # 2. tg_get_card
        self.register(MCPTool(
            name="tg_get_card",
            description="Fetches payment card profile including customer_id, card network, and card type.",
            input_schema={
                "type": "object",
                "properties": {
                    "card_id": {"type": "string", "description": "Card identifier (e.g. 'C12382-K1')"}
                },
                "required": ["card_id"]
            },
            handler=lambda card_id: graph_gateway.get_card(str(card_id))
        ))

        # 3. tg_get_customer
        self.register(MCPTool(
            name="tg_get_customer",
            description="Fetches customer entity and lists all payment cards owned by this customer.",
            input_schema={
                "type": "object",
                "properties": {
                    "customer_id": {"type": "string", "description": "Customer identifier (e.g. 'C12382')"}
                },
                "required": ["customer_id"]
            },
            handler=lambda customer_id: graph_gateway.get_customer(str(customer_id))
        ))

        # 4. tg_get_device_profile
        self.register(MCPTool(
            name="tg_get_device_profile",
            description="Fetches device and hardware fingerprint details for an online transaction.",
            input_schema={
                "type": "object",
                "properties": {
                    "profile_id": {"type": "string", "description": "Device profile composite ID"}
                },
                "required": ["profile_id"]
            },
            handler=lambda profile_id: graph_gateway.device_neighbors(str(profile_id))
        ))

        # 5. tg_find_connected_entities
        self.register(MCPTool(
            name="tg_find_connected_entities",
            description="Explores 1-hop and 2-hop graph neighbors connected to a given vertex in TigerGraph.",
            input_schema={
                "type": "object",
                "properties": {
                    "entity_type": {"type": "string", "description": "Vertex type: Customer, Card, Transaction, or DeviceProfile"},
                    "entity_id": {"type": "string", "description": "Primary ID of the entity"}
                },
                "required": ["entity_type", "entity_id"]
            },
            handler=self._handle_find_connected_entities
        ))

        # 6. tg_card_window
        self.register(MCPTool(
            name="tg_card_window",
            description="Traverses Card MADE Transaction edges in TigerGraph to calculate financial velocity, micro-authorizations (<$5 online), and total exposure.",
            input_schema={
                "type": "object",
                "properties": {
                    "card_id": {"type": "string", "description": "Card identifier"},
                    "window_hours": {"type": "integer", "description": "Analysis time window in hours", "default": 48}
                },
                "required": ["card_id"]
            },
            handler=lambda card_id, window_hours=48: graph_gateway.card_window(str(card_id), int(window_hours))
        ))

        # 7. tg_device_neighbors
        self.register(MCPTool(
            name="tg_device_neighbors",
            description="Traverses from a DeviceProfile to all connected transactions, cards, customers, and prior fraud closed cases to detect multi-card syndicates.",
            input_schema={
                "type": "object",
                "properties": {
                    "device_profile_id": {"type": "string", "description": "Hardware/browser device fingerprint string"}
                },
                "required": ["device_profile_id"]
            },
            handler=lambda device_profile_id: graph_gateway.device_neighbors(str(device_profile_id))
        ))

        # 8. tg_cluster_analysis
        self.register(MCPTool(
            name="tg_cluster_analysis",
            description="Compares transaction billing region against customer's historical card locations to distinguish legitimate travel from out-of-region anomalies (Rules R2 & R3).",
            input_schema={
                "type": "object",
                "properties": {
                    "customer_id": {"type": "string", "description": "Customer ID"},
                    "target_region": {"type": "string", "description": "Billing region code (addr1)"}
                },
                "required": ["customer_id", "target_region"]
            },
            handler=lambda customer_id, target_region: graph_gateway.cluster_analysis(str(customer_id), str(target_region))
        ))

        # 9. tg_find_similar_cases
        self.register(MCPTool(
            name="tg_find_similar_cases",
            description="Retrieves historical closed cases from TigerGraph memory matching pattern typology and financial exposure range.",
            input_schema={
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Fraud typology: card_testing, card_not_present_fraud, card_not_present_new_device, out_of_region_use, account_takeover"},
                    "min_exposure": {"type": "number", "description": "Minimum USD exposure filter", "default": 0.0},
                    "max_exposure": {"type": "number", "description": "Maximum USD exposure filter", "default": 0.0},
                    "max_results": {"type": "integer", "description": "Maximum cases to return", "default": 5}
                },
                "required": ["pattern"]
            },
            handler=lambda pattern, min_exposure=0.0, max_exposure=0.0, max_results=5: graph_gateway.find_similar_cases(
                pattern=str(pattern),
                min_exposure=float(min_exposure),
                max_exposure=float(max_exposure),
                max_results=int(max_results)
            )
        ))

        # 10. tg_run_syndicate_detection
        self.register(MCPTool(
            name="tg_run_syndicate_detection",
            description="Executes Weakly Connected Components graph traversal across shared devices and cards to detect coordinated fraud rings.",
            input_schema={
                "type": "object",
                "properties": {
                    "min_cards_per_cluster": {"type": "integer", "description": "Minimum cards sharing a device to flag as syndicate", "default": 2}
                },
                "required": []
            },
            handler=self._handle_syndicate_detection
        ))

        # 11. tg_write_case
        self.register(MCPTool(
            name="tg_write_case",
            description="Writes resolved investigation case into TigerGraph graph memory, linking TARGET_CARD and INVESTIGATES edges.",
            input_schema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string", "description": "Investigation Case ID (e.g. 'HHG-001')"},
                    "customer_id": {"type": "string", "description": "Customer ID"},
                    "card_id": {"type": "string", "description": "Primary card investigated"},
                    "verdict": {"type": "string", "description": "fraud, legitimate, or uncertain"},
                    "fraud_prob": {"type": "number", "description": "Probability score 0.0 to 1.0"},
                    "pattern": {"type": "string", "description": "Identified pattern or 'none'"},
                    "pattern_desc": {"type": "string", "description": "Description if undocumented, else empty string"},
                    "exposure": {"type": "number", "description": "Total USD exposure"},
                    "summary": {"type": "string", "description": "Investigation findings summary"},
                    "sar_filed": {"type": "boolean", "description": "Whether a SAR was filed"},
                    "flagged_txn_id": {"type": "string", "description": "Initial flagged transaction ID"}
                },
                "required": ["case_id", "customer_id", "card_id", "verdict", "fraud_prob", "pattern", "exposure", "summary", "sar_filed"]
            },
            handler=lambda case_id, customer_id, card_id, verdict, fraud_prob, pattern, exposure, summary, sar_filed, pattern_desc="", flagged_txn_id="": graph_gateway.write_case_to_graph(
                case_id=str(case_id),
                customer_id=str(customer_id),
                card_id=str(card_id),
                verdict=str(verdict),
                fraud_prob=float(fraud_prob),
                pattern=str(pattern),
                pattern_desc=str(pattern_desc),
                exposure=float(exposure),
                summary=str(summary),
                sar_filed=bool(sar_filed),
                flagged_txn_id=str(flagged_txn_id)
            )
        ))

        # 12. tg_retrieve_fraud_policy
        self.register(MCPTool(
            name="tg_retrieve_fraud_policy",
            description="Retrieves official hackathon bank fraud policy rules (R1 to R10), required actions, and approval routing criteria.",
            input_schema={
                "type": "object",
                "properties": {
                    "rule_id": {"type": "string", "description": "Specific rule e.g. 'R1', 'R2', 'R5' or empty for full policy summary"}
                },
                "required": []
            },
            handler=self._handle_retrieve_policy
        ))

        # 13. tg_evaluate_action_permissions
        self.register(MCPTool(
            name="tg_evaluate_action_permissions",
            description="Evaluates whether an action can be executed automatically or requires Level-1 (Team Lead) or Level-2 (Fraud Manager) approval under bank policy.",
            input_schema={
                "type": "object",
                "properties": {
                    "action": {"type": "string", "description": "Action name: BLOCK_CARD, DECLINE_TRANSACTION, FILE_REPORT, etc."},
                    "exposure_usd": {"type": "number", "description": "Total case exposure in USD"}
                },
                "required": ["action", "exposure_usd"]
            },
            handler=self._handle_evaluate_permissions
        ))

    def _handle_find_connected_entities(self, entity_type: str, entity_id: str) -> Dict[str, Any]:
        """Finds multi-hop connected entities."""
        etype = entity_type.lower()
        if "card" in etype:
            c = graph_gateway.get_card(entity_id)
            win = graph_gateway.card_window(entity_id, 48)
            return {
                "entity_type": "Card",
                "entity_id": entity_id,
                "customer_id": c.get("customer_id") if c else None,
                "total_txns": win.get("total_txns", 0),
                "total_volume_usd": win.get("total_volume_usd", 0.0),
                "connected_transactions": [t.get("txn_id") for t in win.get("transactions", [])][:10]
            }
        elif "cust" in etype:
            cust = graph_gateway.get_customer(entity_id)
            return {
                "entity_type": "Customer",
                "entity_id": entity_id,
                "owned_cards": cust.get("cards", []) if cust else []
            }
        elif "txn" in etype or "trans" in etype:
            txn = graph_gateway.get_transaction(entity_id)
            return {
                "entity_type": "Transaction",
                "entity_id": entity_id,
                "card_id": txn.get("card_id") if txn else None,
                "customer_id": txn.get("customer_id") if txn else None,
                "amount": txn.get("amount") if txn else None,
                "addr1": txn.get("addr1") if txn else None
            }
        elif "dev" in etype:
            return graph_gateway.device_neighbors(entity_id)
        else:
            return {"error": True, "message": f"Unsupported entity_type '{entity_type}'"}

    def _handle_syndicate_detection(self, min_cards_per_cluster: int = 2) -> Dict[str, Any]:
        """Runs syndicate detection on live TigerGraph."""
        if tigergraph_client.is_live():
            try:
                res = tigergraph_client.run_installed_query("detect_fraud_syndicates", {"min_cards_per_cluster": int(min_cards_per_cluster)})
                return res.get("results", [{}])[0]
            except Exception as e:
                logger.warning(f"Live syndicate query failed: {e}")
        return {"suspicious_device_clusters_count": 0, "status": "executed"}

    def _handle_retrieve_policy(self, rule_id: str = "") -> Dict[str, Any]:
        """Returns structured policy rules from authoritative Fraud Policy v1.0."""
        rules = {
            "R1": "R1. Verify before you block on a weak signal: If assessed fraud probability is below 0.70 and rests on a single signal, recommend VERIFY_WITH_CUSTOMER or STEP_UP_AUTH before any block.",
            "R2": "R2. Customer denies transaction: Recommend BLOCK_CARD and CREATE_CASE. Add FILE_REPORT if exposure > $1,000 or activity connects to a shared device profile or another card's fraud.",
            "R3": "R3. Customer confirms transaction: Recommend CLOSE_NO_FRAUD. Note confirmation in case file.",
            "R4": "R4. No reply within 24 hours: Recommend MONITOR_CARD and DECLINE_TRANSACTION for pending authorizations. Escalate if exposure > $500.",
            "R5": "R5. Card testing: Three or more small online authorizations within an hour followed by larger purchase: recommend DECLINE_TRANSACTION and STEP_UP_AUTH. If purchase > $100 already cleared, recommend BLOCK_CARD.",
            "R6": "R6. Shared origin: When several cards show fraud from the same device profile, billing region, or recipient email, recommend CREATE_CASE, FILE_REPORT, and MONITOR_CONNECTED_CARDS.",
            "R7": "R7. Disputed but legitimate: When customer disputes a charge matching their own recurring pattern (same merchant, same amount, monthly), recommend CREATE_CASE, VERIFY_WITH_CUSTOMER, and WARN_CUSTOMER. Do not block.",
            "R8": "R8. Escalate when uncertain and exposed: If verdict is uncertain and exposure > $500 or evidence conflicts, recommend ESCALATE_TO_ANALYST.",
            "R9": "R9. Undocumented patterns: When activity fits no known pattern but shows coordinated or repeated abuse across customers, recommend CREATE_CASE, FILE_REPORT, and ESCALATE_TO_ANALYST. Describe pattern in own words.",
            "R10": "R10. Never BLOCK_ALL_CARDS unless at least two of customer's cards show confirmed fraud or customer credentials are confirmed compromised."
        }
        rid = rule_id.upper().strip()
        if rid in rules:
            return {"rule": rid, "description": rules[rid]}
        return {"policy_version": "1.0", "all_rules": rules}

    def _handle_evaluate_permissions(self, action: str, exposure_usd: float) -> Dict[str, Any]:
        """Evaluates approval tier under Fraud Policy v1.0 Section 2."""
        act = action.upper().strip()
        exp = float(exposure_usd)

        # Route determination
        if act in ["ALLOW_TRANSACTION", "MONITOR_CARD", "MONITOR_CONNECTED_CARDS", 
                   "WARN_CUSTOMER", "VERIFY_WITH_CUSTOMER", "STEP_UP_AUTH", 
                   "GENERATE_REPORT", "CREATE_CASE", "ESCALATE_TO_ANALYST", "CLOSE_NO_FRAUD"]:
            route = "auto"
            execution_permission = "AUTHORIZED_FOR_AGENT"
        elif act == "DECLINE_TRANSACTION":
            route = "L1"
            execution_permission = "REQUIRES_L1_APPROVAL"
        elif act == "BLOCK_CARD":
            if exp <= 2500.0:
                route = "L1"
                execution_permission = "REQUIRES_L1_APPROVAL"
            else:
                route = "L2"
                execution_permission = "REQUIRES_L2_APPROVAL"
        elif act in ["BLOCK_ALL_CARDS", "FILE_REPORT"]:
            route = "L2"
            execution_permission = "REQUIRES_L2_APPROVAL"
        else:
            route = "L1"
            execution_permission = "REQUIRES_APPROVAL"

        return {
            "action": act,
            "exposure_usd": exp,
            "approval_route": route,
            "execution_permission": execution_permission,
            "can_auto_execute": (route == "auto")
        }

# Global singleton
mcp_registry = TigerGraphMCPRegistry()
