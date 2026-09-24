#!/usr/bin/env python3
"""
Integration Test Suite for TigerGraph Model Context Protocol (MCP) Layer.
Validates tool registration, schema definitions, live execution, validation,
and permission evaluation.
"""

import sys
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.mcp.tools import mcp_registry

class TestTigerGraphMCP(unittest.TestCase):

    def test_01_tool_registration(self):
        """Verify all required MCP tools are registered."""
        tools = mcp_registry.list_tools()
        names = {t["name"] for t in tools}
        required_tools = [
            "tg_get_transaction",
            "tg_get_card",
            "tg_get_customer",
            "tg_get_device_profile",
            "tg_find_connected_entities",
            "tg_card_window",
            "tg_device_neighbors",
            "tg_cluster_analysis",
            "tg_find_similar_cases",
            "tg_run_syndicate_detection",
            "tg_write_case",
            "tg_retrieve_fraud_policy",
            "tg_evaluate_action_permissions"
        ]
        for rt in required_tools:
            self.assertIn(rt, names, f"Missing MCP tool: {rt}")

    def test_02_get_transaction_and_card(self):
        """Test retrieving transaction and card details via MCP."""
        res_txn = mcp_registry.execute_tool("tg_get_transaction", {"txn_id": "3514030"})
        self.assertFalse(res_txn.get("error"))
        self.assertEqual(res_txn["result"]["txn_id"], "3514030")
        card_id = res_txn["result"]["card_id"]

        res_card = mcp_registry.execute_tool("tg_get_card", {"card_id": card_id})
        self.assertFalse(res_card.get("error"))
        self.assertEqual(res_card["result"]["card_id"], card_id)

    def test_03_card_window_live_execution(self):
        """Test executing card_window on live TigerGraph via MCP."""
        res = mcp_registry.execute_tool("tg_card_window", {"card_id": "C12382-K1", "window_hours": 48})
        self.assertFalse(res.get("error"))
        result = res.get("result", {})
        self.assertEqual(result.get("card_id"), "C12382-K1")
        self.assertGreater(result.get("total_txns", 0), 0)

    def test_04_cluster_analysis_execution(self):
        """Test cluster analysis region anomaly detection via MCP."""
        res = mcp_registry.execute_tool("tg_cluster_analysis", {"customer_id": "C12382", "target_region": "444.0"})
        self.assertFalse(res.get("error"))
        self.assertEqual(res["result"]["customer_id"], "C12382")

    def test_05_find_similar_cases_execution(self):
        """Test case memory retrieval via MCP."""
        res = mcp_registry.execute_tool("tg_find_similar_cases", {"pattern": "card_testing", "max_results": 3})
        self.assertFalse(res.get("error"))
        cases = res["result"]
        self.assertIsInstance(cases, list)
        self.assertGreater(len(cases), 0)
        self.assertEqual(cases[0]["pattern"], "card_testing")

    def test_06_policy_retrieval(self):
        """Test retrieving official policy rules."""
        res_r1 = mcp_registry.execute_tool("tg_retrieve_fraud_policy", {"rule_id": "R1"})
        self.assertFalse(res_r1.get("error"))
        self.assertIn("Verify before you block", res_r1["result"]["description"])

        res_all = mcp_registry.execute_tool("tg_retrieve_fraud_policy", {})
        self.assertFalse(res_all.get("error"))
        self.assertEqual(res_all["result"]["policy_version"], "1.0")

    def test_07_action_permission_routing(self):
        """Test evaluating approval routes under policy."""
        # auto action
        r_auto = mcp_registry.execute_tool("tg_evaluate_action_permissions", {"action": "VERIFY_WITH_CUSTOMER", "exposure_usd": 150.0})
        self.assertEqual(r_auto["result"]["approval_route"], "auto")
        self.assertTrue(r_auto["result"]["can_auto_execute"])

        # L1 action: decline or block <= $2,500
        r_l1 = mcp_registry.execute_tool("tg_evaluate_action_permissions", {"action": "BLOCK_CARD", "exposure_usd": 1200.0})
        self.assertEqual(r_l1["result"]["approval_route"], "L1")
        self.assertFalse(r_l1["result"]["can_auto_execute"])

        # L2 action: block > $2,500 or file report
        r_l2_block = mcp_registry.execute_tool("tg_evaluate_action_permissions", {"action": "BLOCK_CARD", "exposure_usd": 4000.0})
        self.assertEqual(r_l2_block["result"]["approval_route"], "L2")

        r_l2_sar = mcp_registry.execute_tool("tg_evaluate_action_permissions", {"action": "FILE_REPORT", "exposure_usd": 500.0})
        self.assertEqual(r_l2_sar["result"]["approval_route"], "L2")

    def test_08_validation_and_safe_error(self):
        """Test that missing required arguments fail safely with clean error code."""
        res = mcp_registry.execute_tool("tg_card_window", {})
        self.assertTrue(res.get("error"))
        self.assertEqual(res.get("code"), "INVALID_ARGUMENT")
        self.assertIn("Missing required parameter", res.get("message"))

if __name__ == "__main__":
    unittest.main()
