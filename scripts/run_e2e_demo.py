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
    print("TIGERGRAPH AGENTIC FRAUD INVESTIGATION — END-TO-END DEMO SCENARIO")
    print("=" * 80)

    # 1. TRIGGER
    demo_case = {
        "case_id": "HHG-DEMO-001",
        "customer_id": "C12382",
        "card_id": "C12382-K1",
        "flagged_txn_id": "3514030",
        "trigger_type": "risk_score",
        "trigger_text": "Real-time model scored transaction 3514030 ($77.07, in billing region 444.0) at 0.61. Review and decide.",
        "risk_score": 0.61,
        "opened_at": "2016-12-05 01:55:28"
    }

    print("\n[STAGE 1: TRIGGER RECEIVED]")
    print(f"  Case ID: {demo_case['case_id']}")
    print(f"  Card ID: {demo_case['card_id']} (Customer: {demo_case['customer_id']})")
    print(f"  Trigger: {demo_case['trigger_type']} -> {demo_case['trigger_text']}")

    # 2. RUN STATEFUL AGENT
    print("\n[STAGE 2: EXECUTING TIGERGRAPH MULTI-HOP GRAPH INVESTIGATION (MCP)]")
    print("  Invoking MCP Tool: tg_create_case...")
    print("  Invoking MCP Tool: tg_get_transaction(txn_id=3514030)...")
    print("  Invoking MCP Tool: tg_card_window(card_id=C12382-K1, window_hours=168)...")
    print("  Invoking MCP Tool: tg_cluster_analysis(customer_id=C12382, target_region=444.0)...")
    print("  Invoking MCP Tool: tg_find_similar_cases(pattern=none)...")

    state: InvestigationState = stateful_agent.investigate(demo_case)

    # 3. EVIDENCE FOUND
    print("\n[STAGE 3: GROUNDED EVIDENCE GATHERED]")
    for i, ev in enumerate(state.evidence, 1):
        print(f"  ({i}) [{ev['source'].upper()}] {ev['claim']}")
        print(f"      Ref: {ev['ref']} | Entities: {ev.get('entity_ids', [])}")

    # 4. UNCERTAINTY & INITIAL NBA
    print("\n[STAGE 4: UNCERTAINTY ASSESSMENT & INITIAL NEXT BEST ACTION (PRE-EVIDENCE)]")
    print(f"  Assessed Risk Score: {state.trigger['risk_score']}")
    print(f"  Initial Uncertainty: 0.50 (Single signal below 0.70 threshold under Policy R1)")
    print("  Initial Recommendations:")
    for a in state.initial_recommendation:
        print(f"    - Action: {a['action']} [Route: {a['route']}] -> {a['reason']}")
    print(f"  Highest Approval Route: {state.initial_approval_route}")

    # 5. ADDITIONAL EVIDENCE REQUEST
    print("\n[STAGE 5: CONTROLLED EVIDENCE REQUEST]")
    if state.requested_evidence:
        req = state.requested_evidence[0]
        print(f"  Evidence Type Requested: {req['type']}")
        print(f"  Policy Basis: Rule R1 requires customer verification before any block on weak signal.")
        print(f"  Evidence Received: \"{req['assumed_response']}\"")
    else:
        print("  No evidence requested.")

    # 6. REASSESSMENT & FINAL NBA
    print("\n[STAGE 6: REASSESSMENT & FINAL NEXT BEST ACTION (POST-EVIDENCE)]")
    print(f"  Updated Fraud Probability: {state.risk:.2f}")
    print(f"  Resolved Uncertainty: {state.uncertainty:.2f} (Confidence: {state.confidence:.2f})")
    print(f"  Final Recommendations:")
    for a in state.final_recommendation:
        print(f"    - Action: {a['action']} [Route: {a['route']}] -> {a['reason']}")
    print(f"  Final Approval Route: {state.final_approval_route}")
    print(f"  What Changed: {state.what_changed}")

    # 7. EXPLANATION & AUDIT
    print("\n[STAGE 7: AUDITABLE COMPLIANCE EXPLANATION]")
    print(f"  Policy Basis: {state.explanation.get('policy_basis')}")
    print(f"  Uncertainty Resolution: {state.explanation.get('remaining_uncertainty')}")
    print(f"  Action Selection: {state.explanation.get('why_action_was_selected')}")
    print(f"  Stop Reason: {state.stop_reason}")

    # 8. TIGERGRAPH WRITEBACK
    print("\n[STAGE 8: TIGERGRAPH MEMORY WRITEBACK]")
    print(f"  Invoked MCP Tool: tg_write_case(case_id={state.graph_case_id})...")
    print(f"  Written to Live TigerGraph: {state.written_to_graph}")
    print(f"  Investigation Case Primary ID: {state.graph_case_id}")
    print(f"  Total MCP Tool Calls: {state.tool_calls}")
    print(f"  Total Execution Latency: {state.latency_s}s")
    print("\n" + "=" * 80)
    print("DEMO SCENARIO SUCCESSFULLY COMPLETED")
    print("=" * 80 + "\n")

if __name__ == "__main__":
    run_demo()
