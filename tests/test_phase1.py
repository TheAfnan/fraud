import os
import sys
import unittest
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.tigergraph.client import tigergraph_client
from backend.tigergraph.gateway import graph_gateway
from backend.tigergraph.data_indexer import get_db_connection

class TestPhase1TigerGraphIntegration(unittest.TestCase):

    def test_01_gsql_files_exist_and_non_empty(self):
        """Verify all authoritative GSQL scripts exist and contain required queries."""
        tg_dir = BASE_DIR / "tigergraph"
        self.assertTrue((tg_dir / "schema.gsql").exists())
        self.assertTrue((tg_dir / "loading_jobs.gsql").exists())
        self.assertTrue((tg_dir / "queries.gsql").exists())

        schema_content = (tg_dir / "schema.gsql").read_text(encoding="utf-8")
        self.assertIn("CREATE VERTEX Customer", schema_content)
        self.assertIn("CREATE VERTEX Card", schema_content)
        self.assertIn("CREATE VERTEX Transaction", schema_content)
        self.assertIn("CREATE VERTEX DeviceProfile", schema_content)
        self.assertIn("CREATE VERTEX ClosedCase", schema_content)
        self.assertIn("CREATE VERTEX InvestigationCase", schema_content)
        self.assertIn("CREATE DIRECTED EDGE OWNS", schema_content)
        self.assertIn("CREATE DIRECTED EDGE MADE", schema_content)
        self.assertIn("CREATE DIRECTED EDGE FROM_DEVICE", schema_content)
        self.assertIn("CREATE DIRECTED EDGE INVOLVES", schema_content)

        queries_content = (tg_dir / "queries.gsql").read_text(encoding="utf-8")
        self.assertIn("card_window", queries_content)
        self.assertIn("device_neighbors", queries_content)
        self.assertIn("cluster_analysis", queries_content)
        self.assertIn("find_similar_cases", queries_content)
        self.assertIn("write_case_to_graph", queries_content)

    def test_02_database_counts(self):
        """Verify exact record counts loaded from dataset."""
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) FROM transactions")
        txns_count = cur.fetchone()[0]
        self.assertEqual(txns_count, 590742, "Expected exactly 590,742 transactions")

        cur.execute("SELECT COUNT(*) FROM identity")
        ident_count = cur.fetchone()[0]
        self.assertEqual(ident_count, 144432, "Expected exactly 144,432 identity records")

        cur.execute("SELECT COUNT(*) FROM closed_cases")
        cases_count = cur.fetchone()[0]
        self.assertEqual(cases_count, 5565, "Expected exactly 5,565 closed cases")

        cur.execute("SELECT COUNT(*) FROM case_pack")
        pack_count = cur.fetchone()[0]
        self.assertEqual(pack_count, 20, "Expected exactly 20 benchmark cases")

        conn.close()

    def test_03_tigergraph_gateway_health(self):
        """Verify graph gateway reports explicit engine health status."""
        status = graph_gateway.get_engine_status()
        self.assertIn("mode", status)
        self.assertIn(status["mode"], ["TIGERGRAPH_LIVE", "LOCAL_FALLBACK"])
        self.assertIn("is_live", status)
        self.assertIn("latency_ms", status)
        print(f"\n[ENGINE STATUS] Active Mode: {status['mode']} | Host: '{status.get('host')}' | Live: {status['is_live']}")

    def test_04_card_window_query(self):
        """Test card_window query traversal and statistics."""
        res = graph_gateway.card_window("C12382-K1", window_hours=48)
        self.assertEqual(res["card_id"], "C12382-K1")
        self.assertGreater(res["total_txns"], 0)
        self.assertIn("micro_auth_count", res)
        self.assertIn("total_volume_usd", res)
        self.assertIn("transactions", res)

    def test_05_device_neighbors_query(self):
        """Test device_neighbors graph traversal for multi-card and closed case links."""
        # Find a device profile that has transactions
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT device_profile FROM identity WHERE device_profile != '|||' LIMIT 1")
        row = cur.fetchone()
        conn.close()

        if row:
            dev_profile = row[0]
            res = graph_gateway.device_neighbors(dev_profile)
            self.assertEqual(res["device_profile_id"], dev_profile)
            self.assertIn("card_count", res)
            self.assertIn("cards", res)
            self.assertIn("cases", res)

    def test_06_cluster_analysis_query(self):
        """Test cluster_analysis region anomaly detection."""
        res = graph_gateway.cluster_analysis("C12382", "444.0")
        self.assertEqual(res["customer_id"], "C12382")
        self.assertIn("total_customer_txns", res)
        self.assertIn("historical_region_distribution", res)

    def test_07_find_similar_cases_query(self):
        """Test find_similar_cases graph memory retrieval."""
        res = graph_gateway.find_similar_cases("card_testing", max_results=3)
        self.assertIsInstance(res, list)
        self.assertLessEqual(len(res), 3)
        for c in res:
            self.assertEqual(c["pattern"], "card_testing")

    def test_08_write_case_to_graph(self):
        """Test writing an investigation case vertex to graph."""
        res = graph_gateway.write_case_to_graph(
            case_id="TEST-CASE-001",
            customer_id="C12382",
            card_id="C12382-K1",
            verdict="fraud",
            fraud_prob=0.85,
            pattern="card_testing",
            pattern_desc="Testing writeback",
            exposure=250.0,
            summary="Test case summary",
            sar_filed=True,
            flagged_txn_id="3514030"
        )
        self.assertIn("case_id", res)
        self.assertEqual(res["case_id"], "TEST-CASE-001")

if __name__ == "__main__":
    unittest.main()
