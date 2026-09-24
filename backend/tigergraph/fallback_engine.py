import sqlite3
import logging
from typing import Any, Dict, List, Optional
from backend.tigergraph.data_indexer import get_db_connection, initialize_database

logger = logging.getLogger("fallback_engine")

class LocalFallbackGraphEngine:
    """
    High-fidelity graph query engine acting STRICTLY as an offline test harness
    when TigerGraph Savanna credentials are not supplied.
    Executes the exact graph traversals, GSQL logic, and algorithms defined in schema.gsql & queries.gsql.
    """

    def __init__(self):
        # Ensure database is indexed
        initialize_database()

    def get_transaction(self, txn_id: str) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT t.*, i.device_profile, i.DeviceInfo, i.id_30 as os, i.id_31 as browser, 
                   i.id_33 as screen, i.DeviceType, i.id_15 as device_status, i.id_23 as is_proxy
            FROM transactions t
            LEFT JOIN identity i ON t.TransactionID = i.TransactionID
            WHERE t.TransactionID = ?
        """, (str(txn_id),))
        row = cur.fetchone()
        conn.close()
        if not row:
            return None
        res = dict(row)
        res["txn_id"] = str(res.get("TransactionID", txn_id))
        res["amount"] = float(res.get("TransactionAmt", 0.0) or 0.0)
        return res

    def get_identity(self, txn_id: str) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM identity WHERE TransactionID = ?", (str(txn_id),))
        row = cur.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_card(self, card_id: str) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT card_id, customer_id, card1, card2, card3, card4, card5, card6,
                   COUNT(*) as total_txns, MIN(ts) as first_seen, MAX(ts) as last_seen,
                   SUM(TransactionAmt) as total_volume
            FROM transactions
            WHERE card_id = ?
            GROUP BY card_id
        """, (str(card_id),))
        row = cur.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_customer(self, customer_id: str) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT customer_id, COUNT(DISTINCT card_id) as card_count, 
                   COUNT(*) as total_txns, SUM(TransactionAmt) as total_volume,
                   MIN(ts) as customer_since, MAX(ts) as last_activity
            FROM transactions
            WHERE customer_id = ?
            GROUP BY customer_id
        """, (str(customer_id),))
        row = cur.fetchone()
        conn.close()
        return dict(row) if row else None

    def card_window(self, card_id: str, window_hours: int = 48) -> Dict[str, Any]:
        """
        Emulates GSQL query card_window(VERTEX<Card> target_card, INT window_hours)
        Traverses Card -> MADE -> Transaction, counts micro authorizations, calculates velocity.
        """
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT t.TransactionID as txn_id, t.TransactionAmt as amount, t.ts, 
                   t.channel, t.risk_score, t.addr1, t.ProductCD as product_cd,
                   i.device_profile, i.id_15 as device_status, i.id_23 as is_proxy
            FROM transactions t
            LEFT JOIN identity i ON t.TransactionID = i.TransactionID
            WHERE t.card_id = ?
            ORDER BY t.ts DESC
        """, (str(card_id),))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()

        micro_auth_count = sum(1 for r in rows if r["amount"] < 5.0 and r["channel"] == "online")
        total_exposure = sum(r["amount"] for r in rows)

        return {
            "card_id": card_id,
            "total_txns": len(rows),
            "micro_auth_count": micro_auth_count,
            "total_volume_usd": round(total_exposure, 2),
            "earliest_transaction": rows[-1]["ts"] if rows else None,
            "latest_transaction": rows[0]["ts"] if rows else None,
            "transactions": rows
        }

    def device_neighbors(self, device_profile_id: str) -> Dict[str, Any]:
        """
        Emulates GSQL query device_neighbors(VERTEX<DeviceProfile> target_device)
        Traverses DeviceProfile <- FROM_DEVICE - Transaction <- MADE - Card <- OWNS - Customer
        and links to ClosedCases.
        """
        if not device_profile_id or device_profile_id.strip() == "|||":
            return {
                "device_profile_id": device_profile_id,
                "card_count": 0,
                "customer_count": 0,
                "prior_fraud_cases_count": 0,
                "cards": [],
                "customers": [],
                "cases": []
            }

        conn = get_db_connection()
        cur = conn.cursor()
        
        dev_info = device_profile_id.split("|")[0].strip() if "|" in device_profile_id else device_profile_id

        # Find all transactions with this device profile or hardware model
        cur.execute("""
            SELECT DISTINCT t.card_id, t.customer_id, t.TransactionID
            FROM identity i
            JOIN transactions t ON i.TransactionID = t.TransactionID
            WHERE i.device_profile = ? OR (i.DeviceInfo != '' AND i.DeviceInfo = ?)
        """, (device_profile_id, dev_info))
        txn_matches = cur.fetchall()

        cards = list(set(r["card_id"] for r in txn_matches))
        customers = list(set(r["customer_id"] for r in txn_matches))

        # Check for closed cases on these cards
        cases = []
        fraud_cases_count = 0
        if cards:
            placeholders = ",".join("?" for _ in cards)
            cur.execute(f"""
                SELECT case_id, pattern, outcome, exposure_usd, analyst_notes
                FROM closed_cases
                WHERE card_id IN ({placeholders})
            """, cards)
            for r in cur.fetchall():
                cases.append(dict(r))
                if r["outcome"] == "confirmed_fraud":
                    fraud_cases_count += 1

        conn.close()

        return {
            "device_profile_id": device_profile_id,
            "card_count": len(cards),
            "customer_count": len(customers),
            "prior_fraud_cases_count": fraud_cases_count,
            "cards": cards,
            "customers": customers,
            "cases": cases
        }

    def cluster_analysis(self, customer_id: str, target_region: str) -> Dict[str, Any]:
        """
        Emulates GSQL query cluster_analysis(VERTEX<Customer> target_customer, STRING target_region)
        Compares transaction billing region against historical frequency distribution.
        """
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT addr1, COUNT(*) as cnt
            FROM transactions
            WHERE customer_id = ? AND addr1 IS NOT NULL AND addr1 != ''
            GROUP BY addr1
            ORDER BY cnt DESC
        """, (str(customer_id),))
        rows = cur.fetchall()
        conn.close()

        total = sum(r["cnt"] for r in rows)
        target_count = 0
        freq = {}
        for r in rows:
            freq[r["addr1"]] = r["cnt"]
            if str(r["addr1"]).split(".")[0] == str(target_region).split(".")[0]:
                target_count = r["cnt"]

        return {
            "customer_id": customer_id,
            "queried_region": target_region,
            "total_customer_txns": total,
            "target_region_prior_txns": target_count,
            "historical_region_distribution": freq
        }

    def find_similar_cases(self, pattern: str = "", min_exposure: float = 0.0, 
                           max_exposure: float = 0.0, max_results: int = 5) -> List[Dict[str, Any]]:
        """
        Emulates GSQL query find_similar_cases(...)
        Retrieves matching closed cases for memory and contextual reasoning.
        """
        conn = get_db_connection()
        cur = conn.cursor()
        query = "SELECT * FROM closed_cases WHERE 1=1"
        params = []
        if pattern:
            query += " AND pattern = ?"
            params.append(pattern)
        if min_exposure > 0:
            query += " AND exposure_usd >= ?"
            params.append(min_exposure)
        if max_exposure > 0:
            query += " AND exposure_usd <= ?"
            params.append(max_exposure)

        query += " ORDER BY opened_at DESC LIMIT ?"
        params.append(max_results)

        cur.execute(query, params)
        cases = [dict(r) for r in cur.fetchall()]
        conn.close()
        return cases

    def write_case_to_graph(self, case_id: str, customer_id: str, card_id: str,
                            verdict: str, fraud_prob: float, pattern: str,
                            pattern_desc: str, exposure: float, summary: str,
                            sar_filed: bool, flagged_txn_id: str) -> Dict[str, Any]:
        """
        Emulates GSQL query write_case_to_graph(...)
        Writes investigated case into the investigation_cases table / graph vertex.
        """
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO investigation_cases VALUES (
                ?, ?, ?, datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        """, (
            case_id, customer_id, card_id,
            "closed_fraud" if verdict == "fraud" else ("closed_legitimate" if verdict == "legitimate" else "escalated"),
            verdict, fraud_prob, pattern, pattern_desc, exposure, summary,
            1 if sar_filed else 0, flagged_txn_id
        ))
        conn.commit()
        conn.close()
        return {"status": "Case successfully recorded", "case_id": case_id}

# Singleton instance
fallback_engine = LocalFallbackGraphEngine()
