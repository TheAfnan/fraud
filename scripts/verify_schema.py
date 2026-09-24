#!/usr/bin/env python3
"""
TigerGraph Savanna Live Schema Verification Script
Queries TigerGraph REST++ / GSQL API to inspect and display
the live vertex types, edge types, attributes, and graph metadata.
"""

import sys
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

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

def main():
    print("============================================================================")
    print("      TigerGraph Savanna Live Schema Verification Report                    ")
    print("============================================================================")
    
    health = tigergraph_client.check_health()
    print(f"Target Host : {health.get('host') or '(Not configured in .env)'}")
    print(f"Target Graph: {health.get('graph')}")
    print(f"Mode        : {health.get('mode')}")
    print(f"Live Status : {health.get('status')}")
    print(f"Latency     : {health.get('latency_ms')} ms")

    if health.get("mode") != "TIGERGRAPH_LIVE":
        print("\n[VERIFICATION BLOCKED] Cannot verify schema in LOCAL_FALLBACK mode.")
        print(f"Details: {health.get('error')}")
        print("\nPlease configure .env with live TG_HOST, TG_USERNAME, TG_PASSWORD, TG_SECRET.")
        sys.exit(1)

    # Fetch live schema
    meta = tigergraph_client.get_schema_metadata()
    if meta.get("error"):
        print(f"\n[API ERROR] Failed to fetch schema: {meta.get('error')}")
        sys.exit(1)

    live_vtypes = meta.get("vertex_types", [])
    live_etypes = meta.get("edge_types", [])

    print(f"\nTotal Live Vertex Types: {len(live_vtypes)}")
    for i, v in enumerate(sorted(live_vtypes), 1):
        req_flag = " [REQUIRED]" if v in REQUIRED_VERTICES else ""
        print(f"  {i}. {v}{req_flag}")

    print(f"\nTotal Live Edge Types: {len(live_etypes)}")
    for i, e in enumerate(sorted(live_etypes), 1):
        req_flag = " [REQUIRED]" if e in REQUIRED_EDGES else ""
        print(f"  {i}. {e}{req_flag}")

    # Check completeness
    missing_v = [v for v in REQUIRED_VERTICES if v not in live_vtypes]
    missing_e = [e for e in REQUIRED_EDGES if e not in live_etypes]

    print("\n--- Compliance Audit ---")
    if not missing_v and not missing_e:
        print("[STATUS: PASS] All 8 required vertex types and 12 edge types are LIVE in FraudGraph.")
        sys.exit(0)
    else:
        if missing_v:
            print(f"[STATUS: FAIL] Missing Vertices: {missing_v}")
        if missing_e:
            print(f"[STATUS: FAIL] Missing Edges: {missing_e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
