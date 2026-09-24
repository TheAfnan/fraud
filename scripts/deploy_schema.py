#!/usr/bin/env python3
"""
TigerGraph Savanna / Community Edition Schema Deployment Script
Applies the authoritative schema from tigergraph/schema.gsql to the live TigerGraph instance
using TigerGraph's supported GSQL SCHEMA_CHANGE JOB mechanism.
"""

import sys
import os
from pathlib import Path

# Add project root to path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.config import TG_HOST, TG_GRAPH, TG_USERNAME, TG_PASSWORD, TG_SECRET, TG_API_TOKEN
from backend.tigergraph.client import tigergraph_client

REQUIRED_VERTICES = [
    "Customer",
    "Card",
    "Transaction",
    "DeviceProfile",
    "EmailDomain",
    "BillingRegion",
    "ClosedCase",
    "InvestigationCase"
]

REQUIRED_EDGES = [
    "OWNS",
    "MADE",
    "FROM_DEVICE",
    "PURCHASER_EMAIL",
    "BILLED_IN",
    "NEXT",
    "INVOLVES",
    "ON_CARD",
    "CONNECTED_TO",
    "INVESTIGATES",
    "TARGET_CARD",
    "CONNECTED_CARD"
]

def build_schema_change_job(graph_name: str) -> str:
    """
    Constructs a GSQL SCHEMA_CHANGE JOB matching tigergraph/schema.gsql
    to apply all 8 vertices and 12 edges to an existing graph.
    """
    gsql = f"""
USE GRAPH {graph_name}

// Drop existing job if any was left behind from a previous run
DROP JOB schema_deploy_hhgoa

CREATE SCHEMA_CHANGE JOB schema_deploy_hhgoa FOR GRAPH {graph_name} {{
    // 1. Customer Vertex
    ADD VERTEX Customer (
        PRIMARY_ID customer_id STRING,
        customer_id STRING
    ) WITH STATS="OUTDEGREE_BY_EDGETYPE";

    // 2. Card Vertex
    ADD VERTEX Card (
        PRIMARY_ID card_id STRING,
        card_id STRING,
        customer_id STRING,
        card1 STRING,
        card2 STRING,
        card3 STRING,
        card4 STRING,
        card5 STRING,
        card6 STRING
    ) WITH STATS="OUTDEGREE_BY_EDGETYPE";

    // 3. Transaction Vertex
    ADD VERTEX Transaction (
        PRIMARY_ID txn_id STRING,
        txn_id STRING,
        amount DOUBLE,
        ts DATETIME,
        product_cd STRING,
        channel STRING,
        risk_score DOUBLE,
        addr1 STRING,
        addr2 STRING,
        dist1 DOUBLE,
        dist2 DOUBLE
    ) WITH STATS="OUTDEGREE_BY_EDGETYPE";

    // 4. DeviceProfile Vertex
    ADD VERTEX DeviceProfile (
        PRIMARY_ID profile_id STRING,
        profile_id STRING,
        device_info STRING,
        os STRING,
        browser STRING,
        screen STRING,
        device_type STRING,
        is_proxy STRING
    ) WITH STATS="OUTDEGREE_BY_EDGETYPE";

    // 5. EmailDomain Vertex
    ADD VERTEX EmailDomain (
        PRIMARY_ID domain STRING,
        domain STRING
    ) WITH STATS="OUTDEGREE_BY_EDGETYPE";

    // 6. BillingRegion Vertex
    ADD VERTEX BillingRegion (
        PRIMARY_ID region_code STRING,
        region_code STRING
    ) WITH STATS="OUTDEGREE_BY_EDGETYPE";

    // 7. ClosedCase Vertex
    ADD VERTEX ClosedCase (
        PRIMARY_ID case_id STRING,
        case_id STRING,
        customer_id STRING,
        card_id STRING,
        opened_at DATETIME,
        closed_at DATETIME,
        outcome STRING,
        pattern STRING,
        first_fraud_txn_id STRING,
        n_txns INT,
        exposure_usd DOUBLE,
        actions_taken STRING,
        report_filed STRING,
        analyst_notes STRING
    ) WITH STATS="OUTDEGREE_BY_EDGETYPE";

    // 8. InvestigationCase Vertex
    ADD VERTEX InvestigationCase (
        PRIMARY_ID case_id STRING,
        case_id STRING,
        customer_id STRING,
        card_id STRING,
        opened_at DATETIME,
        status STRING,
        verdict STRING,
        fraud_probability DOUBLE,
        pattern STRING,
        pattern_description STRING,
        exposure_usd DOUBLE,
        summary STRING,
        sar_filed BOOL
    ) WITH STATS="OUTDEGREE_BY_EDGETYPE";

    // Directed Edges with Reverse Edges
    ADD DIRECTED EDGE OWNS (FROM Customer, TO Card) WITH REVERSE_EDGE="OWNED_BY";
    ADD DIRECTED EDGE MADE (FROM Card, TO Transaction) WITH REVERSE_EDGE="MADE_BY";
    ADD DIRECTED EDGE FROM_DEVICE (FROM Transaction, TO DeviceProfile, device_status STRING) WITH REVERSE_EDGE="DEVICE_OF";
    ADD DIRECTED EDGE PURCHASER_EMAIL (FROM Transaction, TO EmailDomain) WITH REVERSE_EDGE="EMAIL_OF_TXN";
    ADD DIRECTED EDGE BILLED_IN (FROM Transaction, TO BillingRegion) WITH REVERSE_EDGE="REGION_OF_TXN";
    ADD DIRECTED EDGE NEXT (FROM Transaction, TO Transaction, time_delta_sec INT) WITH REVERSE_EDGE="PREV";
    ADD DIRECTED EDGE INVOLVES (FROM ClosedCase, TO Transaction) WITH REVERSE_EDGE="INVOLVED_IN_CASE";
    ADD DIRECTED EDGE ON_CARD (FROM ClosedCase, TO Card) WITH REVERSE_EDGE="HAS_CLOSED_CASE";
    ADD DIRECTED EDGE CONNECTED_TO (FROM ClosedCase, TO Card) WITH REVERSE_EDGE="CONNECTED_CLOSED_CASE";
    ADD DIRECTED EDGE INVESTIGATES (FROM InvestigationCase, TO Transaction) WITH REVERSE_EDGE="CASE_INVESTIGATING";
    ADD DIRECTED EDGE TARGET_CARD (FROM InvestigationCase, TO Card) WITH REVERSE_EDGE="INVESTIGATED_BY";
    ADD DIRECTED EDGE CONNECTED_CARD (FROM InvestigationCase, TO Card) WITH REVERSE_EDGE="CONNECTED_INVESTIGATION";
}}

RUN SCHEMA_CHANGE JOB schema_deploy_hhgoa
DROP JOB schema_deploy_hhgoa
"""
    return gsql

def main():
    print("============================================================================")
    print("      TigerGraph Savanna Schema Deployment — HHGOA FraudGraph               ")
    print("============================================================================")
    
    # 1. Health check
    health = tigergraph_client.check_health()
    print(f"Target Host : {health.get('host') or '(Not configured in .env)'}")
    print(f"Target Graph: {health.get('graph')}")
    print(f"Mode        : {health.get('mode')}")
    print(f"Latency     : {health.get('latency_ms')} ms")

    if health.get("mode") != "TIGERGRAPH_LIVE":
        print("\n[DEPLOYMENT BLOCKED] Cannot deploy schema in LOCAL_FALLBACK mode.")
        print("Reason: TigerGraph instance is either unconfigured or unreachable.")
        if health.get("error"):
            print(f"Error Details: {health['error']}")
        print("\nTo fix:")
        print("1. Create or edit .env in track5/ with your Savanna credentials:")
        print("   TG_HOST=https://your-solution.i.tgcloud.io")
        print("   TG_GRAPH=FraudGraph")
        print("   TG_USERNAME=tigergraph")
        print("   TG_PASSWORD=your_password")
        print("   TG_SECRET=your_secret")
        print("2. Re-run: python scripts/deploy_schema.py")
        sys.exit(1)

    print("\n[SUCCESS] Connected to live TigerGraph instance.")

    # 2. Acquire token if secret is present
    if tigergraph_client.secret and not tigergraph_client.token:
        print("Requesting TigerGraph REST++ token using TG_SECRET...")
        tok = tigergraph_client.request_token()
        if tok:
            print("Token acquired: [REDACTED]")
        else:
            print("Notice: Could not acquire Bearer token via secret, proceeding with Basic Auth credentials.")

    # 3. Build & execute GSQL schema change job
    target_graph = tigergraph_client.graph or "FraudGraph"
    print(f"\nConstructing GSQL SCHEMA_CHANGE JOB for graph '{target_graph}'...")
    gsql_script = build_schema_change_job(target_graph)
    
    print("Executing GSQL SCHEMA_CHANGE JOB on TigerGraph Savanna...")
    res = tigergraph_client.execute_gsql(gsql_script)

    print("\n--- GSQL Deployment Output ---")
    print(res.get("output", "").strip() or "(No output text)")
    print("------------------------------")

    if not res.get("success", False):
        print(f"\n[DEPLOYMENT FAILED] GSQL execution error: {res.get('error')}")
        sys.exit(1)

    print("\n[DEPLOYMENT EXECUTED] Schema change job executed successfully.")

    # 4. Verification via live REST++ schema metadata
    print("\nVerifying live schema metadata via TigerGraph REST++ API...")
    schema_meta = tigergraph_client.get_schema_metadata(target_graph)

    live_vtypes = set(schema_meta.get("vertex_types", []))
    live_etypes = set(schema_meta.get("edge_types", []))

    print(f"Live Vertex Types in '{target_graph}': {sorted(list(live_vtypes))}")
    print(f"Live Edge Types in '{target_graph}'  : {sorted(list(live_etypes))}")

    missing_vertices = [v for v in REQUIRED_VERTICES if v not in live_vtypes]
    missing_edges = [e for e in REQUIRED_EDGES if e not in live_etypes]

    has_errors = False
    if missing_vertices:
        print(f"\n[ERROR] Missing Vertex Types: {missing_vertices}")
        has_errors = True
    else:
        print(f"\n[VERIFIED] All {len(REQUIRED_VERTICES)} required vertex types exist.")

    if missing_edges:
        print(f"\n[ERROR] Missing Edge Types: {missing_edges}")
        has_errors = True
    else:
        print(f"[VERIFIED] All {len(REQUIRED_EDGES)} required edge types exist.")

    if has_errors:
        print("\n[VERIFICATION FAILED] Live graph schema is incomplete.")
        sys.exit(1)

    print("\n============================================================================")
    print(" [SUCCESS] TigerGraph live schema deployment and verification COMPLETE!    ")
    print("============================================================================")

if __name__ == "__main__":
    main()
