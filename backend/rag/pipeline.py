"""
Grounded GraphRAG Context Pipeline.
Combines TigerGraph live graph traversals, closed case memory, official bank policy,
and regulatory red flag ontologies into a compact, case-specific reasoning package.
"""

from typing import Any, Dict, List, Optional
import logging
from backend.mcp.client import mcp_client

logger = logging.getLogger("graph_rag_pipeline")

REGULATORY_TYPOLOGIES = {
    "card_testing": {
        "title": "Card Testing & Micro-Authorization Probing",
        "guidance": "FinCEN Advisory FIN-2011-A016 / FATF Cyber-Enabled Fraud: Rapid series of nominal online authorizations (<$5.00) utilized by illicit actors to validate stolen PAN/CVV validity prior to high-value extraction.",
        "red_flags": ["Burst of 3+ micro-authorizations within 60 minutes", "Non-standard merchant category code", "Subsequent authorization attempt >$50"]
    },
    "card_not_present_fraud": {
        "title": "Card-Not-Present (CNP) Identity Theft",
        "guidance": "FFIEC Fraud & Identity Theft Guidance: Remote electronic commerce transaction conducted without physical card presentation, exhibiting deviation from habitual cardholder velocity or category profile.",
        "red_flags": ["Transaction velocity spike within 48 hours", "Unfamiliar digital merchant", "Cardholder repudiation"]
    },
    "card_not_present_new_device": {
        "title": "CNP Fraud via Unauthenticated Hardware Fingerprint",
        "guidance": "FinCEN Identity-Related Suspicious Activity (2021): Unauthorized digital commerce executed through newly observed device fingerprint or anonymizing proxy infrastructure.",
        "red_flags": ["Device status marked 'New'", "Anonymous proxy or VPN IP routing", "Screen/OS mismatch with account history"]
    },
    "out_of_region_use": {
        "title": "Out-of-Region Physical Compromise (Card Cloning)",
        "guidance": "FFIEC BSA/AML Red Flags: Card-present point-of-sale activity in geographic/billing regions inconsistent with established cardholder history while concurrent activity occurs at home origin.",
        "red_flags": ["Card-present transaction in unvisited billing region (addr1)", "Zero prior transaction history in region", "Absence of travel indicators"]
    },
    "account_takeover": {
        "title": "Account Takeover & Credential Theft",
        "guidance": "FinCEN Advisory FIN-2011-A016 on Account Takeover: Malicious actor gains unauthorized control over cardholder credentials, exhibiting multi-channel deviations and match flag failures.",
        "red_flags": ["Rapid channel switching", "Match flag (M1-M9) failures", "Multiple device modifications"]
    },
    "undocumented": {
        "title": "Coordinated Multi-Account Fraud Syndicate",
        "guidance": "FATF Professional Money Laundering & Syndicate Schemes: Coordinated exploitation sharing underlying technical artifacts (hardware fingerprint, billing clusters, recipient emails) across multiple victim cardholders.",
        "red_flags": ["Identical device profile observed on >1 card accounts", "Cross-account temporal synchronization", "Synthetic identity links"]
    }
}

class GroundedGraphRAGPipeline:
    """
    Constructs a grounded, auditable evidence and reasoning context for fraud investigations.
    """

    def __init__(self, client=None):
        self.client = client or mcp_client

    def retrieve_grounded_context(self,
                                  case_id: str,
                                  card_id: str,
                                  customer_id: str,
                                  flagged_txn_id: str,
                                  suspected_pattern: str,
                                  exposure_usd: float) -> Dict[str, Any]:
        """
        Retrieves compact, relevant multi-source context grounding the investigation.
        """
        # 1. Retrieve Historical Case Memory via MCP
        retrieval_pattern = suspected_pattern if suspected_pattern in REGULATORY_TYPOLOGIES else ""
        similar_cases = self.client.call_tool("tg_find_similar_cases", {
            "pattern": retrieval_pattern,
            "min_exposure": 0.0,
            "max_exposure": 0.0,
            "max_results": 3
        })
        if not isinstance(similar_cases, list):
            similar_cases = []

        # 2. Retrieve Relevant Policy Rules via MCP
        policy_doc = self.client.call_tool("tg_retrieve_fraud_policy", {})
        all_rules = policy_doc.get("all_rules", {})

        # Select relevant rules based on typology & exposure
        relevant_rules = {}
        if suspected_pattern == "card_testing":
            relevant_rules["R5"] = all_rules.get("R5", "")
        elif suspected_pattern in ["card_not_present_fraud", "card_not_present_new_device"]:
            relevant_rules["R1"] = all_rules.get("R1", "")
            relevant_rules["R2"] = all_rules.get("R2", "")
        elif suspected_pattern == "out_of_region_use":
            relevant_rules["R2"] = all_rules.get("R2", "")
            relevant_rules["R3"] = all_rules.get("R3", "")
        elif suspected_pattern == "undocumented":
            relevant_rules["R6"] = all_rules.get("R6", "")
            relevant_rules["R9"] = all_rules.get("R9", "")

        # Always include baseline escalation & R10 safety rule
        relevant_rules["R8"] = all_rules.get("R8", "")
        relevant_rules["R10"] = all_rules.get("R10", "")

        # 3. Regulatory Typology Context
        typology_context = REGULATORY_TYPOLOGIES.get(suspected_pattern, {
            "title": "Unclassified Transaction Activity",
            "guidance": "Standard FFIEC/FinCEN baseline monitoring principles.",
            "red_flags": ["Model score divergence", "Behavioral anomaly"]
        })

        return {
            "case_id": case_id,
            "precedent_cases": similar_cases,
            "applicable_policy_rules": relevant_rules,
            "regulatory_typology": typology_context
        }

    def generate_auditable_explanation(self,
                                       evidence_list: List[Dict[str, Any]],
                                       graph_findings: List[str],
                                       policy_basis: str,
                                       uncertainty_assessment: str,
                                       evidence_request_rationale: str,
                                       action_selection_rationale: str) -> Dict[str, Any]:
        """
        Structures an auditable, non-hallucinatory explanation for compliance review.
        """
        return {
            "evidence_used": [ev.get("claim", "") for ev in evidence_list],
            "relevant_graph_findings": graph_findings,
            "policy_basis": policy_basis,
            "remaining_uncertainty": uncertainty_assessment,
            "why_additional_evidence_was_requested": evidence_request_rationale,
            "why_action_was_selected": action_selection_rationale
        }

rag_pipeline = GroundedGraphRAGPipeline()
