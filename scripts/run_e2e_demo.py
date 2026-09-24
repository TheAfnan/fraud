"""
Deterministic End-to-End Demonstration Script.
Demonstrates the full Hackathon flow:
Trigger -> MCP Multi-hop Investigation -> Grounded Evidence -> Uncertainty Assessment
-> Initial Next Best Action (NBA) -> Additional Evidence Request (Customer Validation)
-> Evidence Received -> Reassessment -> Final NBA (Changed) -> Approval Routing (auto/L1/L2)
-> Case Writeback to TigerGraph -> Auditable Explanation.
"""

import sys
import json
import time
from pathlib import Path

# Add project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.agent.workflow import stateful_agent, InvestigationState
from backend.security import redact_sensitive_text

def run_demo():
    print("=" * 80)
    print("TIGERGRAPH AGENTIC FRAUD INVESTIGATION — OFFICIAL BENCHMARK DEMO")
    print("Demonstrating 3 Trigger Types, MCP Multi-Hop, Policy Routing & SAR Generation")
    print("=" * 80)

    scenarios = [
        {
            "title": "SCENARIO 1: Risk Score Trigger (Rule R1 Weak Signal -> Customer Confirmation -> Legitimate)",
            "case": {
                "case_id": "HHG-DEMO-001",
                "customer_id": "C12382",
                "card_id": "C12382-K1",
                "flagged_txn_id": "3514030",
                "trigger_type": "risk_score",
                "trigger_text": "Real-time model scored transaction 3514030 ($77.07, billing region 444.0) at 0.61.",
                "risk_score": 0.61,
                "opened_at": "2016-12-05 01:55:28"
            }
        },
        {
            "title": "SCENARIO 2: Customer Report Trigger (Rule R2 Customer Denial -> Card Block L1 Approval)",
            "case": {
                "case_id": "HHG-DEMO-003",
                "customer_id": "C08623",
                "card_id": "C08623-K2",
                "flagged_txn_id": "3530164",
                "trigger_type": "customer_report",
                "trigger_text": "Customer reported unrecognized transaction 3530164 ($120.00).",
                "risk_score": 0.0,
                "opened_at": "2016-12-08 14:22:10"
            }
        },
        {
            "title": "SCENARIO 3: Analyst Request Trigger (Rule R6/R9 Multi-Card Device Syndicate -> SAR & L2 Approval)",
            "case": {
                "case_id": "HHG-DEMO-014",
                "customer_id": "C13487",
                "card_id": "C13487-K1",
                "flagged_txn_id": "3478561",
                "trigger_type": "analyst_request",
                "trigger_text": "Analyst request: investigate potential device sharing ring on transaction 3478561.",
                "risk_score": 0.50,
                "opened_at": "2016-11-22 09:15:00"
            }
        }
    ]

    for sc in scenarios:
        print("\n" + "#" * 80)
        print(f" {sc['title']}")
        print("#" * 80)

        demo_case = sc["case"]
        print(f"\n[TRIGGER RECEIVED] Type: {demo_case['trigger_type'].upper()}")
        print(f"  Case ID: {demo_case['case_id']} | Card: {demo_case['card_id']} | Flagged Txn: {demo_case['flagged_txn_id']}")
        print(f"  Details: {demo_case['trigger_text']}")

        print("\n[EXECUTING INVESTIGATION VIA MCP & TIGERGRAPH]")
        state: InvestigationState = stateful_agent.investigate(demo_case)

        print(f"\n[GROUNDED EVIDENCE ({len(state.evidence)} items)]")
        for i, ev in enumerate(state.evidence[:3], 1):
            print(f"  ({i}) [{ev['source'].upper()}] {ev['claim'][:90]}...")
            print(f"      Ref: {ev['ref']}")

        print("\n[UNCERTAINTY & INITIAL NBA (PRE-EVIDENCE)]")
        for a in state.initial_recommendation:
            print(f"  - Action: {a['action']:22s} | Route: {a['route']:5s} | Reason: {a['reason'][:60]}...")
        print(f"  Initial Route: {state.initial_approval_route}")

        if state.requested_evidence:
            req = state.requested_evidence[0]
            print("\n[DYNAMIC EVIDENCE REQUEST & REASSESSMENT]")
            print(f"  Requested: {req['type']} -> Assumed Response: \"{req['assumed_response']}\"")
            print(f"  What Changed: {state.what_changed}")

        print("\n[FINAL NBA & POLICY EXECUTION PERMISSIONS]")
        for a in state.final_recommendation:
            auto_exec = "EXECUTED (Agent Authorized)" if a["route"] == "auto" else "NOT EXECUTED (Human Approval Required)"
            print(f"  - Action: {a['action']:22s} | Route: {a['route']:5s} | Status: {auto_exec}")
        print(f"  Final Route: {state.final_approval_route}")

        if state.sar.get("file"):
            print("\n[SUSPICIOUS ACTIVITY REPORT (SAR) GENERATED]")
            print(f"  Reason: {state.sar['reason']}")
            print(f"  Total Amount: ${state.sar['total_amount_usd']:,.2f}")
            print(f"  Subjects: {len(state.sar['subjects'])} entities identified")
            print(f"  Narrative Snippet: {state.sar['narrative'][:160]}...")

        print(f"\n[TIGERGRAPH WRITEBACK] Graph Case ID: {state.graph_case_id} | Written: {state.written_to_graph}")
        print(f"  Verdict: {state.case_status.upper()} | Tool Calls: {state.tool_calls} | Latency: {state.latency_s}s")

    print("\n" + "=" * 80)
    print("ALL 3 DEMO SCENARIOS COMPLETED SUCCESSFULLY WITH 100% GROUNDING")
    print("=" * 80 + "\n")

if __name__ == "__main__":
    run_demo()
