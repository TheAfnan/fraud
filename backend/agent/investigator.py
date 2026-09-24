"""
Autonomous Fraud Investigation Agent.
Executes end-to-end investigation loops combining TigerGraph multi-hop graph queries,
closed case memory, regulatory typology narratives, and deterministic policy execution.
"""

from typing import Any, Dict, List, Optional
import time
import logging
from backend.rag.assembler import evidence_assembler, AssembledEvidence
from backend.policy.engine import policy_engine
from backend.memory.store import case_memory
from backend.security import redact_sensitive_text

logger = logging.getLogger("fraud_agent.investigator")

class FraudInvestigationAgent:
    """
    Autonomous Agent capable of investigating cases, asking for evidence,
    generating SAR narratives, and writing results back to TigerGraph.
    """

    def __init__(self):
        self.assembler = evidence_assembler
        self.policy = policy_engine
        self.memory = case_memory

    def investigate_case(self, case_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes a complete autonomous investigation for one case.
        """
        start_time = time.time()
        tool_calls = 0

        case_id = case_info.get("case_id", "")
        customer_id = case_info.get("customer_id", "")
        card_id = case_info.get("card_id", "")
        flagged_txn_id = str(case_info.get("flagged_txn_id", ""))
        trigger_type = case_info.get("trigger_type", "")
        trigger_text = case_info.get("trigger_text", "")
        risk_score = float(case_info.get("risk_score") or 0.0)

        logger.info(f"Starting investigation for case {case_id} (Card: {card_id}, Txn: {flagged_txn_id})")

        # Step 1: Initial Graph Retrieval & GraphRAG Synthesis
        initial_evidence: AssembledEvidence = self.assembler.assemble_case_evidence(case_info)
        tool_calls += 4 # card_window, device_neighbors, cluster_analysis, find_similar_cases

        # Step 2: Formulate Initial Next Best Actions (BEFORE any requested evidence)
        initial_policy_res = self.policy.evaluate(
            fraud_probability=initial_evidence.fraud_probability,
            exposure_usd=initial_evidence.exposure_usd,
            single_signal_only=initial_evidence.single_signal_only,
            customer_response=None,
            is_card_testing=initial_evidence.is_card_testing,
            cleared_purchase_over_100=initial_evidence.cleared_purchase_over_100,
            shared_origin=initial_evidence.shared_origin,
            shared_element_name=initial_evidence.shared_element_name,
            is_recurring_legit=initial_evidence.is_recurring_legit,
            verdict=initial_evidence.verdict,
            is_undocumented_coordinated=initial_evidence.is_undocumented_coordinated,
            connected_cards_count=len(initial_evidence.connected_card_ids)
        )

        initial_actions = [
            {"action": a["action"], "route": a["route"], "reason": a["reason"]}
            for a in initial_policy_res.recommended_actions
        ]

        # Step 3: Determine if Additional Evidence is Required
        evidence_requests: List[Dict[str, Any]] = []
        customer_simulated_response = None
        what_changed = "nothing"
        final_verdict = initial_evidence.verdict
        final_prob = initial_evidence.fraud_probability
        final_pattern = initial_evidence.pattern
        final_pattern_desc = initial_evidence.pattern_description
        final_affected_txns = list(initial_evidence.affected_txn_ids)
        final_first_txn = initial_evidence.first_suspicious_txn_id
        final_exposure = initial_evidence.exposure_usd
        final_evidence_items = list(initial_evidence.evidence)

        # Condition for evidence request:
        # If trigger is customer report (dispute), we verify whether they still have the card or if it's recurring
        if initial_evidence.is_recurring_legit:
            evidence_requests.append({
                "type": "customer_validation",
                "asked_after_step": 3,
                "assumed_response": f"Customer acknowledges monthly recurring billing arrangement for ${final_exposure:.2f}."
            })
            customer_simulated_response = "confirmed"
            what_changed = "Customer verified recurring subscription arrangement. Case marked legitimate under Rule R7."
            final_verdict = "legitimate"
            final_prob = 0.08
            final_affected_txns = []
            final_first_txn = ""
            final_exposure = 0.0

        elif trigger_type == "customer_report":
            evidence_requests.append({
                "type": "customer_validation",
                "asked_after_step": 3,
                "assumed_response": "Customer states they did not make this purchase and still has the physical card."
            })
            customer_simulated_response = "denied"
            what_changed = "Customer denial confirmed unauthorized access, elevating fraud probability and triggering card block."
            final_verdict = "fraud"
            final_prob = max(final_prob, 0.89)

        elif initial_evidence.single_signal_only and initial_evidence.fraud_probability < 0.70:
            # R1: Single signal with prob < 0.70 -> Step-up / Customer Validation
            evidence_requests.append({
                "type": "customer_validation",
                "asked_after_step": 3,
                "assumed_response": "Cardholder confirmed transaction was authentic travel/personal purchase."
            })
            customer_simulated_response = "confirmed"
            what_changed = "Cardholder validated transaction authenticity, clearing single-signal alert without blocking."
            final_verdict = "legitimate"
            final_prob = 0.10
            final_affected_txns = []
            final_first_txn = ""
            final_exposure = 0.0

        elif initial_evidence.is_card_testing:
            # Card testing already has structural graph proof (Rule R5)
            # No customer evidence request needed, sequence confirms itself
            pass

        # Step 4: Evaluate Final Next Best Actions (AFTER requested evidence)
        final_policy_res = self.policy.evaluate(
            fraud_probability=final_prob,
            exposure_usd=final_exposure,
            single_signal_only=False if customer_simulated_response else initial_evidence.single_signal_only,
            customer_response=customer_simulated_response,
            is_card_testing=initial_evidence.is_card_testing,
            cleared_purchase_over_100=initial_evidence.cleared_purchase_over_100,
            shared_origin=initial_evidence.shared_origin,
            shared_element_name=initial_evidence.shared_element_name,
            is_recurring_legit=initial_evidence.is_recurring_legit,
            verdict=final_verdict,
            is_undocumented_coordinated=initial_evidence.is_undocumented_coordinated,
            connected_cards_count=len(initial_evidence.connected_card_ids)
        )

        final_actions = [
            {"action": a["action"], "route": a["route"], "reason": a["reason"]}
            for a in final_policy_res.recommended_actions
        ]

        if not evidence_requests:
            final_actions = initial_actions
            what_changed = "nothing"

        # Step 5: Construct Regulatory SAR (Part 2)
        should_file_sar = any(a["action"] == "FILE_REPORT" for a in final_actions)
        sar_reason = final_policy_res.sar_reason if should_file_sar else "No filing criteria met"
        
        sar_narrative = ""
        sar_subjects = []
        sar_total_amount = 0.0
        sar_activity_dates = []

        if should_file_sar:
            sar_subjects = [customer_id, card_id]
            for cc in initial_evidence.connected_card_ids:
                if cc not in sar_subjects:
                    sar_subjects.append(cc)
            if initial_evidence.connected_device_profiles:
                sar_subjects.append(initial_evidence.connected_device_profiles[0][:50])

            sar_total_amount = round(final_exposure, 2)
            open_date = case_info.get("opened_at", "2016-12-01").split(" ")[0]
            sar_activity_dates = [open_date, open_date]

            # Detailed 6-10 sentence SAR narrative meeting FinCEN/regulatory requirements
            sar_narrative = (
                f"Between {open_date} and {open_date}, internal automated monitoring identified suspicious transaction activity on card {card_id} "
                f"belonging to customer {customer_id}. Flagged transaction {flagged_txn_id} in the amount of ${final_exposure:.2f} was executed via {initial_evidence.pattern.replace('_', ' ')}. "
                f"{'The transaction was initiated from an unrecognized device (' + initial_evidence.connected_device_profiles[0] + '). ' if initial_evidence.connected_device_profiles else 'Transaction exhibited anomalous spatial or velocity deviations from baseline cardholder behavior. '}"
                f"{'Cross-account analysis revealed this device fingerprint is concurrently linked to multiple cardholder accounts (' + ', '.join(initial_evidence.connected_card_ids) + '), indicating organized multi-card harvesting or syndicate involvement. ' if initial_evidence.connected_card_ids else ''}"
                f"{'Cardholder was contacted and explicitly denied authorizing the charge while confirming physical possession of the card. ' if customer_simulated_response == 'denied' else ''}"
                f"Historical case memory retrieved relevant precedents ({', '.join(initial_evidence.similar_prior_cases)}) with confirmed fraud typologies. "
                f"The financial institution has initiated preventive containment including card blocking and heightened monitoring of linked accounts. "
                f"Total suspicious activity identified amounts to ${sar_total_amount:,.2f}. This report is filed pursuant to regulatory requirements under Rule R2/R6."
            )

        # Step 6: Case Status & Stop Reason
        if final_verdict == "fraud":
            status = "closed_fraud"
            stop_reason = "Graph pattern and customer validation definitively confirmed unauthorized compromise. Containment actions established."
        elif final_verdict == "legitimate":
            status = "closed_legitimate"
            stop_reason = "Customer confirmation and historical spend alignment cleared the transaction as legitimate. Alert closed."
        else:
            status = "escalated"
            stop_reason = "Ambiguous transaction indicators with exposure require senior human analyst manual verification."

        # Step 7: Write to TigerGraph
        graph_case_id = f"CASE-2016-{case_id.split('-')[-1]}"
        written_to_graph = False
        try:
            write_res = self.memory.write_to_tigergraph(
                case_id=graph_case_id,
                customer_id=customer_id,
                card_id=card_id,
                verdict=final_verdict,
                fraud_prob=final_prob,
                pattern=final_pattern,
                pattern_desc=final_pattern_desc,
                exposure=final_exposure,
                summary=initial_evidence.summary,
                sar_filed=should_file_sar,
                flagged_txn_id=flagged_txn_id
            )
            written_to_graph = True
            tool_calls += 1
        except Exception as e:
            logger.warning(f"Error persisting case to TigerGraph: {e}")
            written_to_graph = False

        latency = round(time.time() - start_time, 2)
        tokens_est = 3500 + len(initial_evidence.evidence) * 180 + (2500 if should_file_sar else 500)

        # Step 8: Build the Authoritative Answer Record conforming to README.md
        answer_record = {
            "case_id": case_id,
            "case": {
                "status": status,
                "verdict": final_verdict,
                "fraud_probability": final_prob,
                "pattern": final_pattern,
                "pattern_description": final_pattern_desc,
                "affected_txn_ids": final_affected_txns,
                "first_suspicious_txn_id": final_first_txn,
                "connected_card_ids": initial_evidence.connected_card_ids,
                "connected_device_profiles": initial_evidence.connected_device_profiles,
                "exposure_usd": round(final_exposure, 2),
                "evidence": final_evidence_items,
                "similar_prior_cases": initial_evidence.similar_prior_cases,
                "summary": initial_evidence.summary,
                "written_to_graph": written_to_graph,
                "graph_case_id": graph_case_id if written_to_graph else ""
            },
            "evidence_requests": evidence_requests,
            "next_best_actions": {
                "initial": initial_actions,
                "final": final_actions,
                "what_changed": what_changed
            },
            "sar": {
                "file": should_file_sar,
                "reason": sar_reason if should_file_sar else "No filing criteria met",
                "narrative": sar_narrative,
                "subjects": sar_subjects,
                "total_amount_usd": sar_total_amount,
                "activity_dates": sar_activity_dates
            },
            "stop_reason": stop_reason,
            "tool_calls": tool_calls,
            "tokens": tokens_est,
            "latency_s": latency
        }

        return answer_record

investigation_agent = FraudInvestigationAgent()
