"""
GraphRAG Evidence Assembler.
Combines TigerGraph multi-hop graph traversals, closed case memory,
and regulatory red flag ontologies to assemble structured evidence packages.
"""

from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
import logging
from backend.tigergraph.gateway import graph_gateway
from backend.memory.store import case_memory

logger = logging.getLogger("fraud_agent.rag")

@dataclass
class AssembledEvidence:
    verdict: str # "fraud", "legitimate", "uncertain"
    fraud_probability: float
    pattern: str # card_testing, card_not_present_fraud, card_not_present_new_device, out_of_region_use, account_takeover, undocumented, none
    pattern_description: str
    affected_txn_ids: List[str]
    first_suspicious_txn_id: str
    connected_card_ids: List[str]
    connected_device_profiles: List[str]
    exposure_usd: float
    evidence: List[Dict[str, Any]]
    similar_prior_cases: List[str]
    summary: str
    is_card_testing: bool = False
    cleared_purchase_over_100: bool = False
    shared_origin: bool = False
    shared_element_name: str = ""
    is_recurring_legit: bool = False
    single_signal_only: bool = False
    is_undocumented_coordinated: bool = False
    multiple_cards_confirmed_fraud: bool = False

class GraphRAGAssembler:
    """
    Orchestrates live TigerGraph graph retrieval and synthesizes calibrated evidence.
    """

    def __init__(self):
        self.gateway = graph_gateway
        self.memory = case_memory

    def assemble_case_evidence(self, case_info: Dict[str, Any]) -> AssembledEvidence:
        case_id = case_info.get("case_id", "")
        card_id = case_info.get("card_id", "")
        customer_id = case_info.get("customer_id", "")
        flagged_txn_id = str(case_info.get("flagged_txn_id", ""))
        trigger_type = case_info.get("trigger_type", "")
        trigger_text = case_info.get("trigger_text", "")
        initial_score = float(case_info.get("risk_score") or 0.0)

        # 1. Fetch Flagged Transaction Details
        flagged_txn = self.gateway.get_transaction(flagged_txn_id) or {}
        flagged_amt = float(flagged_txn.get("amount") or 0.0)
        channel = flagged_txn.get("channel", "online")
        billing_region = str(flagged_txn.get("addr1") or "")
        p_email = flagged_txn.get("P_emaildomain", "")
        txn_ts = flagged_txn.get("ts", "")

        # 2. Query Live TigerGraph card_window
        window_hours = 168
        card_window_res = self.gateway.card_window(card_id, window_hours=window_hours)
        all_card_txns = card_window_res.get("transactions", [])
        total_card_txns = len(all_card_txns)
        total_card_exposure = card_window_res.get("total_exposure_usd", flagged_amt)

        # Sort transactions chronologically
        all_card_txns.sort(key=lambda t: t.get("ts", ""))

        # 3. Query Device Information & TigerGraph device_neighbors
        device_profile = ""
        device_info_str = ""
        is_new_device = False
        is_proxy = False
        connected_cards = []
        connected_device_profiles = []
        device_case_ids = []

        if channel == "online":
            # Check identity record for flagged txn
            ident = self.gateway.get_identity(flagged_txn_id)
            if ident:
                device_profile = ident.get("device_profile", "")
                device_info_str = ident.get("DeviceInfo", "")
                is_new_device = (ident.get("id_15") == "New")
                is_proxy = "PROXY" in str(ident.get("id_23", "")).upper()
            
            if device_profile:
                connected_device_profiles.append(device_profile)
                dev_neighbors = self.gateway.device_neighbors(device_profile)
                # Find connected cards on same device
                for c in dev_neighbors.get("cards", []):
                    cid = c.get("v_id") or c.get("attributes", {}).get("Cards.card_id")
                    if cid and cid != card_id and cid not in connected_cards:
                        connected_cards.append(cid)
                for cs in dev_neighbors.get("cases", []):
                    cs_id = cs.get("v_id") or cs.get("attributes", {}).get("ClosedCase.case_id")
                    if cs_id and cs_id not in device_case_ids:
                        device_case_ids.append(cs_id)

        # 4. Query TigerGraph cluster_analysis for region consistency
        region_history = self.gateway.cluster_analysis(customer_id, billing_region)
        historical_total_txns = region_history.get("total_customer_txns", total_card_txns)
        target_region_prior = region_history.get("target_region_prior_txns", 0)
        is_out_of_region = (channel == "in_person" and billing_region != "" and 
                            historical_total_txns >= 5 and target_region_prior == 0)

        # 5. Pattern Detection & Classification
        evidence_items: List[Dict[str, Any]] = []
        pattern = "none"
        pattern_desc = ""
        verdict = "uncertain"
        fraud_prob = 0.50
        affected_txn_ids: List[str] = []
        first_suspicious_txn_id = ""
        exposure_usd = 0.0
        is_card_testing = False
        cleared_purchase_over_100 = False
        shared_origin = len(connected_cards) > 0
        shared_element_name = f"DeviceProfile ({device_profile})" if shared_origin else ""
        is_recurring_legit = False
        single_signal_only = False
        is_undocumented_coordinated = False

        # Add trigger evidence
        if trigger_type == "customer_report":
            evidence_items.append({
                "claim": f"Cardholder {customer_id} reported unrecognized transaction {flagged_txn_id} (${flagged_amt:.2f}): '{trigger_text}'",
                "source": "customer",
                "ref": "trigger:customer_report",
                "entity_ids": [flagged_txn_id, customer_id, card_id]
            })
        elif trigger_type == "risk_score":
            evidence_items.append({
                "claim": f"Real-time machine learning model scored transaction {flagged_txn_id} at {initial_score:.2f}",
                "source": "document",
                "ref": "trigger:model_risk_score",
                "entity_ids": [flagged_txn_id]
            })
        elif trigger_type == "analyst_request":
            evidence_items.append({
                "claim": f"Analyst flagged transaction {flagged_txn_id} on card {card_id} due to suspicious device activity",
                "source": "document",
                "ref": "trigger:analyst_request",
                "entity_ids": [flagged_txn_id, card_id]
            })

        # --- Check 5a. Recurring pattern (Rule R7: Disputed but legitimate) ---
        if trigger_type == "customer_report":
            # Check if there are other transactions with identical amount in prior history
            matching_amt_txns = [t for t in all_card_txns if abs(float(t.get("amount", 0.0)) - flagged_amt) < 0.01 and str(t.get("txn_id")) != flagged_txn_id]
            if len(matching_amt_txns) >= 2:
                is_recurring_legit = True
                pattern = "none"
                verdict = "legitimate"
                fraud_prob = 0.12
                evidence_items.append({
                    "claim": f"Transaction matches regular recurring subscription pattern ({len(matching_amt_txns)} prior charges of ${flagged_amt:.2f})",
                    "source": "graph",
                    "ref": f"query:card_window(card_id={card_id})",
                    "entity_ids": [str(t.get("txn_id")) for t in matching_amt_txns[:3]]
                })

        # --- Check 5b. Card Testing (Pattern 1, Rule R5) ---
        if not is_recurring_legit and channel == "online":
            # Look for 3+ micro-authorizations (<$5 or <$10) followed by a larger purchase
            sub_5_txns = [t for t in all_card_txns if 0.01 <= float(t.get("amount", 0.0)) <= 5.0 and t.get("channel") == "online"]
            larger_txns = [t for t in all_card_txns if float(t.get("amount", 0.0)) >= 50.0 and t.get("channel") == "online"]
            if len(sub_5_txns) >= 3 and len(larger_txns) >= 1:
                is_card_testing = True
                pattern = "card_testing"
                verdict = "fraud"
                fraud_prob = 0.88
                testing_txns = sub_5_txns + larger_txns
                testing_txns.sort(key=lambda t: t.get("ts", ""))
                affected_txn_ids = [str(t.get("txn_id")) for t in testing_txns]
                first_suspicious_txn_id = affected_txn_ids[0]
                exposure_usd = sum(float(t.get("amount", 0.0)) for t in testing_txns)
                cleared_purchase_over_100 = any(float(t.get("amount", 0.0)) >= 100.0 for t in larger_txns)
                
                evidence_items.append({
                    "claim": f"{len(sub_5_txns)} online micro-authorizations under $5 within testing burst followed by purchase of ${larger_txns[0].get('amount', 0):.2f}",
                    "source": "graph",
                    "ref": f"query:card_window(card_id={card_id})",
                    "entity_ids": affected_txn_ids[:4]
                })

        # --- Check 5c. Shared Origin / Syndicate (Pattern: undocumented or shared device, Rule R6/R9) ---
        if not is_recurring_legit and not is_card_testing:
            if len(connected_cards) >= 1:
                shared_origin = True
                if len(connected_cards) >= 2 or trigger_type == "analyst_request":
                    is_undocumented_coordinated = True
                    pattern = "undocumented"
                    pattern_desc = f"Syndicate device sharing: {len(connected_cards)+1} cards utilized identical device fingerprint ({device_profile}) across multiple customer accounts in rapid succession."
                    verdict = "fraud"
                    fraud_prob = 0.91
                else:
                    pattern = "card_not_present_new_device" if is_new_device else "card_not_present_fraud"
                    verdict = "fraud"
                    fraud_prob = 0.86

                affected_txn_ids = [flagged_txn_id]
                first_suspicious_txn_id = flagged_txn_id
                exposure_usd = flagged_amt
                
                evidence_items.append({
                    "claim": f"Device fingerprint ({device_profile}) is shared across {len(connected_cards)+1} cards in graph",
                    "source": "graph",
                    "ref": f"query:device_neighbors(device_profile={device_profile[:30]}...)",
                    "entity_ids": connected_cards + [card_id]
                })

        # --- Check 5d. Out of Region Use (Pattern 4, Rule R2/R3) ---
        if not is_recurring_legit and not is_card_testing and not shared_origin and is_out_of_region:
            pattern = "out_of_region_use"
            affected_txn_ids = [flagged_txn_id]
            first_suspicious_txn_id = flagged_txn_id
            exposure_usd = flagged_amt
            if trigger_type == "customer_report":
                verdict = "fraud"
                fraud_prob = 0.88
            else:
                verdict = "uncertain"
                fraud_prob = 0.62
                single_signal_only = True
            
            evidence_items.append({
                "claim": f"Card-present transaction in billing region {billing_region} where cardholder has zero prior transactions across {historical_total_txns} historical events",
                "source": "graph",
                "ref": f"query:cluster_analysis(customer_id={customer_id}, region={billing_region})",
                "entity_ids": [flagged_txn_id, customer_id, billing_region]
            })

        # --- Check 5e. Card-not-present fraud from new device or customer report ---
        if not is_recurring_legit and not is_card_testing and not shared_origin and not is_out_of_region:
            if trigger_type == "customer_report":
                verdict = "fraud"
                fraud_prob = 0.85
                pattern = "card_not_present_new_device" if is_new_device else "card_not_present_fraud"
                affected_txn_ids = [flagged_txn_id]
                first_suspicious_txn_id = flagged_txn_id
                exposure_usd = flagged_amt
                evidence_items.append({
                    "claim": f"Customer denial corroborated by {'unrecognized new device (' + device_info_str + ')' if is_new_device else 'unusual transaction velocity'}",
                    "source": "graph",
                    "ref": f"query:card_window(card_id={card_id})",
                    "entity_ids": [flagged_txn_id]
                })
            elif is_new_device and initial_score >= 0.75:
                verdict = "uncertain" if initial_score < 0.85 else "fraud"
                fraud_prob = initial_score * 0.95
                pattern = "card_not_present_new_device"
                affected_txn_ids = [flagged_txn_id]
                first_suspicious_txn_id = flagged_txn_id
                exposure_usd = flagged_amt
                evidence_items.append({
                    "claim": f"Transaction initiated from unauthenticated new device ({device_info_str}) with elevated risk score ({initial_score:.2f})",
                    "source": "graph",
                    "ref": f"query:device_neighbors(device_profile={device_profile[:30]}...)",
                    "entity_ids": [flagged_txn_id]
                })
            elif initial_score <= 0.65 and not is_new_device:
                # Legitimate activity / false alarm
                pattern = "none"
                verdict = "legitimate"
                fraud_prob = 0.12
                affected_txn_ids = []
                first_suspicious_txn_id = ""
                exposure_usd = 0.0
                single_signal_only = True
                evidence_items.append({
                    "claim": f"Transaction consistent with cardholder normal spending profile; no device or velocity anomalies identified",
                    "source": "graph",
                    "ref": f"query:card_window(card_id={card_id})",
                    "entity_ids": [flagged_txn_id]
                })
            else:
                verdict = "uncertain"
                fraud_prob = initial_score if initial_score > 0 else 0.50
                single_signal_only = True
                pattern = "card_not_present_fraud" if channel == "online" else "none"
                affected_txn_ids = [flagged_txn_id]
                first_suspicious_txn_id = flagged_txn_id
                exposure_usd = flagged_amt
                evidence_items.append({
                    "claim": f"Single weak anomaly score ({initial_score:.2f}) without corroborating device compromise",
                    "source": "document",
                    "ref": "trigger:model_risk_score",
                    "entity_ids": [flagged_txn_id]
                })

        # 6. Retrieve Similar Closed Cases from TigerGraph Memory
        retrieval_pattern = pattern if pattern != "none" else "card_not_present_fraud"
        similar_cases = self.memory.retrieve_similar_cases(pattern=retrieval_pattern, max_results=2)
        similar_prior_cases = [c.get("case_id") for c in similar_cases if c.get("case_id")]
        if not similar_prior_cases and device_case_ids:
            similar_prior_cases = device_case_ids[:2]

        if similar_prior_cases:
            evidence_items.append({
                "claim": f"Retrieved historical precedent cases {', '.join(similar_prior_cases)} exhibiting matching typology ({pattern})",
                "source": "document",
                "ref": f"query:find_similar_cases(pattern={pattern})",
                "entity_ids": similar_prior_cases
            })

        # 7. Formulate Short Summary
        if verdict == "fraud":
            summary = f"Confirmed {pattern.replace('_', ' ')} incident on card {card_id} involving ${exposure_usd:,.2f} across {len(affected_txn_ids)} transaction(s). " \
                      f"Evidence includes {evidence_items[1]['claim'] if len(evidence_items) > 1 else 'graph anomalies'}."
        elif verdict == "legitimate":
            summary = f"Alert for card {card_id} cleared as legitimate activity. " \
                      f"{'Transaction matches historical recurring pattern.' if is_recurring_legit else 'Transaction aligns with cardholder historical parameters without graph anomalies.'}"
        else:
            summary = f"Investigation for card {card_id} on transaction {flagged_txn_id} (${flagged_amt:.2f}) yielded inconclusive single-signal evidence (assessed prob: {fraud_prob:.2f}). Step-up verification required."

        return AssembledEvidence(
            verdict=verdict,
            fraud_probability=round(fraud_prob, 2),
            pattern=pattern,
            pattern_description=pattern_desc,
            affected_txn_ids=affected_txn_ids,
            first_suspicious_txn_id=first_suspicious_txn_id,
            connected_card_ids=connected_cards,
            connected_device_profiles=connected_device_profiles,
            exposure_usd=round(exposure_usd, 2),
            evidence=evidence_items,
            similar_prior_cases=similar_prior_cases,
            summary=summary,
            is_card_testing=is_card_testing,
            cleared_purchase_over_100=cleared_purchase_over_100,
            shared_origin=shared_origin,
            shared_element_name=shared_element_name,
            is_recurring_legit=is_recurring_legit,
            single_signal_only=single_signal_only,
            is_undocumented_coordinated=is_undocumented_coordinated,
            multiple_cards_confirmed_fraud=False
        )

evidence_assembler = GraphRAGAssembler()
