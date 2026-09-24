"""
Benchmark Pipeline for 20-Case Autonomous Fraud Investigation.
Executes end-to-end against live TigerGraph Savanna, outputs compliant JSON answer files in cases/,
and writes completed investigation cases to the graph database.
"""

import os
import sys
import csv
import json
import time
import logging
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from typing import Any, Dict, List
from backend.agent.investigator import investigation_agent
from backend.tigergraph.gateway import graph_gateway
from backend.security import redact_sensitive_text

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("benchmark_pipeline")

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
CASES_DIR = Path(__file__).resolve().parent.parent.parent / "cases"

def validate_answer_schema(data: Dict[str, Any], case_id: str) -> List[str]:
    """
    Validates that the generated JSON strictly follows the Answer Format in data/README.md.
    """
    errors = []
    top_keys = ["case_id", "case", "evidence_requests", "next_best_actions", "sar", "stop_reason", "tool_calls", "tokens", "latency_s"]
    for k in top_keys:
        if k not in data:
            errors.append(f"Missing top-level key: {k}")

    # Case section
    case = data.get("case", {})
    case_keys = ["status", "verdict", "fraud_probability", "pattern", "pattern_description",
                 "affected_txn_ids", "first_suspicious_txn_id", "connected_card_ids",
                 "connected_device_profiles", "exposure_usd", "evidence", "similar_prior_cases",
                 "summary", "written_to_graph", "graph_case_id"]
    for k in case_keys:
        if k not in case:
            errors.append(f"Missing case key: {k}")

    # Enums
    valid_statuses = {"open", "closed_fraud", "closed_legitimate", "escalated"}
    if case.get("status") not in valid_statuses:
        errors.append(f"Invalid case status: {case.get('status')}")

    valid_verdicts = {"fraud", "legitimate", "uncertain"}
    if case.get("verdict") not in valid_verdicts:
        errors.append(f"Invalid verdict: {case.get('verdict')}")

    valid_patterns = {"card_testing", "card_not_present_fraud", "card_not_present_new_device",
                      "out_of_region_use", "account_takeover", "undocumented", "none"}
    if case.get("pattern") not in valid_patterns:
        errors.append(f"Invalid pattern: {case.get('pattern')}")

    if case.get("pattern") == "undocumented" and not case.get("pattern_description"):
        errors.append("pattern_description is required when pattern is undocumented")

    if case.get("verdict") == "legitimate":
        if case.get("affected_txn_ids"):
            errors.append("affected_txn_ids must be empty for legitimate verdict")
        if case.get("exposure_usd") != 0.0:
            errors.append("exposure_usd must be 0 for legitimate verdict")
        if data.get("sar", {}).get("file"):
            errors.append("sar.file must be false for legitimate verdict")

    # SAR section
    sar = data.get("sar", {})
    for k in ["file", "reason", "narrative", "subjects", "total_amount_usd", "activity_dates"]:
        if k not in sar:
            errors.append(f"Missing sar key: {k}")

    if sar.get("file"):
        if not sar.get("narrative"):
            errors.append("sar.narrative required when sar.file is true")
        if not sar.get("subjects"):
            errors.append("sar.subjects required when sar.file is true")
        if not sar.get("activity_dates") or len(sar.get("activity_dates")) != 2:
            errors.append("sar.activity_dates must have 2 dates when sar.file is true")
    else:
        if sar.get("narrative") != "":
            errors.append("sar.narrative must be '' when sar.file is false")
        if sar.get("subjects") != []:
            errors.append("sar.subjects must be [] when sar.file is false")
        if sar.get("total_amount_usd") != 0:
            errors.append("sar.total_amount_usd must be 0 when sar.file is false")
        if sar.get("activity_dates") != []:
            errors.append("sar.activity_dates must be [] when sar.file is false")

    # Next Best Actions
    nba = data.get("next_best_actions", {})
    for k in ["initial", "final", "what_changed"]:
        if k not in nba:
            errors.append(f"Missing nba key: {k}")

    return errors

def run_benchmark_suite() -> Dict[str, Any]:
    """
    Executes the entire 20-case benchmark suite.
    """
    CASES_DIR.mkdir(parents=True, exist_ok=True)
    case_pack_file = DATA_DIR / "case_pack.csv"

    if not case_pack_file.exists():
        raise FileNotFoundError(f"Case pack not found at {case_pack_file}")

    cases_to_run = []
    with open(case_pack_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cases_to_run.append(row)

    logger.info(f"Loaded {len(cases_to_run)} cases from {case_pack_file}. Starting benchmark run...")
    start_suite_time = time.time()

    results_summary = []
    total_written_to_tg = 0
    total_sar_filed = 0
    validation_failures = 0

    for i, case_info in enumerate(cases_to_run, 1):
        cid = case_info["case_id"]
        logger.info(f"[{i:02d}/{len(cases_to_run)}] Investigating {cid} (Card: {case_info['card_id']}, Txn: {case_info['flagged_txn_id']})...")

        case_res = investigation_agent.investigate_case(case_info)

        # Validate format
        val_errors = validate_answer_schema(case_res, cid)
        if val_errors:
            logger.error(f"Validation errors for {cid}: {val_errors}")
            validation_failures += 1
        else:
            logger.info(f"Schema validation passed for {cid}")

        # Save to cases/<case_id>.json
        out_file = CASES_DIR / f"{cid}.json"
        with open(out_file, "w", encoding="utf-8") as out_f:
            json.dump(case_res, out_f, indent=2)
        logger.info(f"Saved answer file to {out_file}")

        if case_res["case"]["written_to_graph"]:
            total_written_to_tg += 1
        if case_res["sar"]["file"]:
            total_sar_filed += 1

        results_summary.append({
            "case_id": cid,
            "verdict": case_res["case"]["verdict"],
            "pattern": case_res["case"]["pattern"],
            "prob": case_res["case"]["fraud_probability"],
            "exposure": case_res["case"]["exposure_usd"],
            "sar": case_res["sar"]["file"],
            "written_to_tg": case_res["case"]["written_to_graph"],
            "latency": case_res["latency_s"]
        })

    total_duration = round(time.time() - start_suite_time, 2)
    logger.info("=" * 60)
    logger.info(f"BENCHMARK COMPLETED IN {total_duration}s")
    logger.info(f"Total Cases: {len(cases_to_run)}")
    logger.info(f"Saved Files: {len(results_summary)}/20 in cases/")
    logger.info(f"Written to TigerGraph: {total_written_to_tg}/20")
    logger.info(f"SAR Reports Filed: {total_sar_filed}")
    logger.info(f"Validation Failures: {validation_failures}")
    logger.info("=" * 60)

    # Print summary table
    print("\n" + "=" * 90)
    print(f"{'Case ID':<10} | {'Verdict':<12} | {'Pattern':<25} | {'Prob':<6} | {'Exposure':<10} | {'SAR':<5} | {'TG Write'}")
    print("-" * 90)
    for r in results_summary:
        print(f"{r['case_id']:<10} | {r['verdict']:<12} | {r['pattern']:<25} | {r['prob']:<6.2f} | ${r['exposure']:<9.2f} | {str(r['sar']):<5} | {str(r['written_to_tg'])}")
    print("=" * 90 + "\n")

    return {
        "total_cases": len(cases_to_run),
        "total_written_to_tg": total_written_to_tg,
        "total_sar_filed": total_sar_filed,
        "validation_failures": validation_failures,
        "duration_s": total_duration,
        "cases": results_summary
    }

if __name__ == "__main__":
    run_benchmark_suite()
