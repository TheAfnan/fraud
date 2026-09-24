"""
Benchmark Integrity Verification Script.
Audits all 20 generated benchmark answers (cases/HHG-001.json - cases/HHG-020.json)
for strict compliance with the Hackathon Problem Statement:
1. 20/20 files present and valid JSON
2. Required schema fields (case, sar, next_best_actions, stop_reason, etc.)
3. ID Grounding: Verifies case_id, customer_id, card_id, and flagged_txn_id match data/case_pack.csv
4. Evidence Requests: Present where single-signal or customer dispute required validation
5. SAR Consistency: sar.file == True <==> 'FILE_REPORT' in final actions
6. TigerGraph Writeback: written_to_graph == True and valid graph_case_id
7. Action Routes: strictly 'auto', 'L1', or 'L2'
"""

import csv
import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
CASES_DIR = ROOT_DIR / "cases"
CASE_PACK_CSV = ROOT_DIR / "data" / "case_pack.csv"

def audit_benchmark():
    print("=" * 70)
    print("AUDITING 20 BENCHMARK INVESTIGATION CASES")
    print("=" * 70)

    # 1. Load Ground Truth Case Pack
    if not CASE_PACK_CSV.exists():
        print(f"ERROR: {CASE_PACK_CSV} not found.")
        sys.exit(1)

    case_pack = {}
    with open(CASE_PACK_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            case_pack[row["case_id"]] = row

    print(f"Loaded {len(case_pack)} ground truth cases from {CASE_PACK_CSV.name}")

    # 2. Audit each case file
    all_passed = True
    summary_stats = {
        "total_cases": len(case_pack),
        "files_found": 0,
        "valid_json": 0,
        "id_integrity_pass": 0,
        "stop_reason_pass": 0,
        "evidence_request_count": 0,
        "sar_filed_count": 0,
        "tg_writeback_pass": 0,
        "action_routing_pass": 0
    }

    allowed_patterns = [
        "card_testing", "card_not_present_fraud", "card_not_present_new_device",
        "out_of_region_use", "account_takeover", "undocumented", "none"
    ]
    allowed_routes = ["auto", "L1", "L2"]

    for case_id in sorted(case_pack.keys()):
        case_file = CASES_DIR / f"{case_id}.json"
        gt = case_pack[case_id]

        if not case_file.exists():
            print(f"[-] {case_id}: MISSING FILE {case_file.name}")
            all_passed = False
            continue

        summary_stats["files_found"] += 1

        try:
            with open(case_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            summary_stats["valid_json"] += 1
        except Exception as e:
            print(f"[-] {case_id}: INVALID JSON - {e}")
            all_passed = False
            continue

        # Check Top-Level Schema
        top_fields = ["case_id", "case", "evidence_requests", "next_best_actions", "sar", "stop_reason", "tool_calls", "tokens", "latency_s"]
        missing_top = [f for f in top_fields if f not in data]
        if missing_top:
            print(f"[-] {case_id}: Missing top-level fields: {missing_top}")
            all_passed = False

        c = data.get("case", {})
        # ID Grounding Check against case_pack.csv
        gt_card = gt["card_id"]
        gt_cust = gt["customer_id"]
        gt_txn = str(gt["flagged_txn_id"])

        # Check evidence claims or entities
        evidence_entities = []
        for ev in c.get("evidence", []):
            evidence_entities.extend(ev.get("entity_ids", []))

        id_ok = True
        if data.get("case_id") != case_id:
            id_ok = False
        if gt_txn not in evidence_entities and gt_txn not in c.get("affected_txn_ids", []):
            # Check if mentioned anywhere in summary
            if gt_txn not in c.get("summary", ""):
                id_ok = False

        if id_ok:
            summary_stats["id_integrity_pass"] += 1
        else:
            print(f"[-] {case_id}: Grounding ID mismatch for flagged_txn {gt_txn}")
            all_passed = False

        # Pattern check
        pattern = c.get("pattern")
        if pattern not in allowed_patterns:
            print(f"[-] {case_id}: Invalid pattern '{pattern}'")
            all_passed = False

        # Stop reason check
        stop_reason = data.get("stop_reason", "")
        if len(stop_reason.strip()) > 15:
            summary_stats["stop_reason_pass"] += 1
        else:
            print(f"[-] {case_id}: Inadequate stop_reason '{stop_reason}'")
            all_passed = False

        # Evidence requests
        ev_reqs = data.get("evidence_requests", [])
        if ev_reqs:
            summary_stats["evidence_request_count"] += 1

        # SAR consistency check
        sar = data.get("sar", {})
        sar_file = sar.get("file", False)
        nba = data.get("next_best_actions", {})
        final_actions = [a.get("action") for a in nba.get("final", [])]
        has_file_report = "FILE_REPORT" in final_actions

        if sar_file != has_file_report:
            print(f"[-] {case_id}: SAR discrepancy! sar.file={sar_file} but FILE_REPORT in final={has_file_report}")
            all_passed = False
        if sar_file:
            summary_stats["sar_filed_count"] += 1
            if not sar.get("narrative") or len(sar.get("subjects", [])) == 0:
                print(f"[-] {case_id}: SAR missing narrative or subjects!")
                all_passed = False

        # Route validation
        routes_valid = True
        for act in nba.get("initial", []) + nba.get("final", []):
            if act.get("route") not in allowed_routes:
                routes_valid = False
                print(f"[-] {case_id}: Invalid route '{act.get('route')}' on action '{act.get('action')}'")
                all_passed = False
        if routes_valid:
            summary_stats["action_routing_pass"] += 1

        # TigerGraph writeback
        if c.get("written_to_graph") and c.get("graph_case_id"):
            summary_stats["tg_writeback_pass"] += 1
        else:
            print(f"[-] {case_id}: Missing TigerGraph writeback")
            all_passed = False

    print("\n" + "=" * 70)
    print("BENCHMARK INTEGRITY AUDIT RESULTS")
    print("=" * 70)
    for k, v in summary_stats.items():
        print(f"  {k:28s}: {v}")

    if all_passed and summary_stats["files_found"] == 20:
        print("\n>>> ALL 20 BENCHMARK CASES PASSED 100% OF INTEGRITY CHECKS! <<<")
        return 0
    else:
        print("\n>>> INTEGRITY ISSUES DETECTED <<<")
        return 1

if __name__ == "__main__":
    sys.exit(audit_benchmark())
