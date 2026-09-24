"""
Deterministic Fraud Policy Engine based strictly on Hackathon Fraud Policy v1.0.
Evaluates rules R1 through R10, assigns strict approval routes (auto, L1, L2),
and determines execution permissions without relying on LLM guesses.
"""

from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

@dataclass
class PolicyEvaluationResult:
    triggered_rules: List[str]
    recommended_actions: List[Dict[str, Any]]
    risk_factors: List[str]
    missing_evidence: List[str]
    approval_route: str
    execution_permission: str
    rationale: str
    should_file_sar: bool
    sar_reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "triggered_rules": self.triggered_rules,
            "recommended_actions": self.recommended_actions,
            "risk_factors": self.risk_factors,
            "missing_evidence": self.missing_evidence,
            "approval_route": self.approval_route,
            "execution_permission": self.execution_permission,
            "rationale": self.rationale,
            "should_file_sar": self.should_file_sar,
            "sar_reason": self.sar_reason
        }

class FraudPolicyEngine:
    """
    Authoritative Fraud Policy Engine implementing Rules R1 to R10.
    """

    def evaluate(self,
                 fraud_probability: float,
                 exposure_usd: float,
                 single_signal_only: bool = False,
                 customer_response: Optional[str] = None, # "denied", "confirmed", "no_reply", None
                 no_reply_hours: float = 0.0,
                 is_card_testing: bool = False,
                 cleared_purchase_over_100: bool = False,
                 shared_origin: bool = False,
                 shared_element_name: str = "",
                 is_recurring_legit: bool = False,
                 verdict: str = "uncertain",
                 is_undocumented_coordinated: bool = False,
                 multiple_cards_confirmed_fraud: bool = False,
                 credentials_compromised: bool = False,
                 connected_cards_count: int = 0) -> PolicyEvaluationResult:

        triggered_rules: List[str] = []
        actions: List[Dict[str, Any]] = []
        risk_factors: List[str] = []
        missing_evidence: List[str] = []
        should_file_sar = False
        sar_reason = ""

        # --- Rule Evaluation ---

        # R7. Disputed but legitimate (Recurring pattern)
        if is_recurring_legit:
            triggered_rules.append("R7")
            actions.append(self._create_action("CREATE_CASE", "R7: Dispute opened for investigation"))
            actions.append(self._create_action("VERIFY_WITH_CUSTOMER", "R7: Customer verification required on recurring pattern"))
            actions.append(self._create_action("WARN_CUSTOMER", "R7: Informational reminder on recurring charge"))
            risk_factors.append("Recurring billing dispute matches customer historical pattern")

        # R3. Customer confirms transaction
        elif customer_response == "confirmed":
            triggered_rules.append("R3")
            actions.append(self._create_action("CLOSE_NO_FRAUD", "R3: Customer confirmed transaction as legitimate"))

        # R2. Customer denies transaction
        elif customer_response == "denied":
            triggered_rules.append("R2")
            actions.append(self._create_action("BLOCK_CARD", "R2: Customer denied transaction; immediate card block", exposure_usd))
            actions.append(self._create_action("CREATE_CASE", "R2: Case creation on confirmed customer denial"))
            risk_factors.append("Customer explicitly denied authorization")

            # SAR trigger under R2: exposure > 1000 or shared device/another card fraud
            if exposure_usd > 1000.0 or shared_origin:
                should_file_sar = True
                sar_reason = "R2: Customer denial with exposure exceeding $1,000 or shared origin links"
                actions.append(self._create_action("FILE_REPORT", sar_reason))
            if shared_origin and connected_cards_count > 0:
                actions.append(self._create_action("MONITOR_CONNECTED_CARDS", f"R2/R6: Monitor {connected_cards_count} connected card(s)"))

        # R4. No reply within 24 hours
        elif customer_response == "no_reply" and no_reply_hours >= 24.0:
            triggered_rules.append("R4")
            actions.append(self._create_action("MONITOR_CARD", "R4: Cardholder did not respond within 24 hours"))
            actions.append(self._create_action("DECLINE_TRANSACTION", "R4: Decline pending transaction authorization"))
            if exposure_usd > 500.0:
                actions.append(self._create_action("ESCALATE_TO_ANALYST", "R4: Exposure exceeds $500 with unverified activity"))
            missing_evidence.append("Customer transaction verification response pending past 24 hours")

        # R5. Card testing sequence
        elif is_card_testing:
            triggered_rules.append("R5")
            risk_factors.append("Rapid sequence of micro-authorizations (<$5) indicative of card testing")
            if cleared_purchase_over_100:
                actions.append(self._create_action("BLOCK_CARD", "R5: Micro-auth sequence with cleared purchase >$100", exposure_usd))
                actions.append(self._create_action("CREATE_CASE", "R5: Card testing confirmed with cleared loss"))
                if exposure_usd > 1000.0 or shared_origin:
                    should_file_sar = True
                    sar_reason = "R5: Card testing episode with exposure >$1,000 or syndicate link"
                    actions.append(self._create_action("FILE_REPORT", sar_reason))
            else:
                actions.append(self._create_action("DECLINE_TRANSACTION", "R5: Decline pending transaction following testing burst"))
                actions.append(self._create_action("STEP_UP_AUTH", "R5: Step-up authentication required to verify cardholder"))
                actions.append(self._create_action("CREATE_CASE", "R5: Card testing sequence identified"))

        # R6. Shared origin (Hardware fingerprint, billing region, or recipient email)
        elif shared_origin:
            triggered_rules.append("R6")
            elem_desc = f" ({shared_element_name})" if shared_element_name else ""
            risk_factors.append(f"Multiple cards connected through common origin{elem_desc}")
            actions.append(self._create_action("CREATE_CASE", f"R6: Shared origin across multiple cards{elem_desc}"))
            should_file_sar = True
            sar_reason = f"R6: Multi-card syndicate identified via shared origin{elem_desc}"
            actions.append(self._create_action("FILE_REPORT", sar_reason))
            actions.append(self._create_action("MONITOR_CONNECTED_CARDS", f"R6: Heighten monitoring on all cards sharing {shared_element_name or 'origin'}"))

        # R9. Undocumented coordinated pattern
        elif is_undocumented_coordinated:
            triggered_rules.append("R9")
            risk_factors.append("Coordinated abusive pattern across customer accounts not matching standard typologies")
            actions.append(self._create_action("CREATE_CASE", "R9: Undocumented coordinated abuse pattern"))
            should_file_sar = True
            sar_reason = "R9: Coordinated, undocumented abuse pattern requiring regulatory notice"
            actions.append(self._create_action("FILE_REPORT", sar_reason))
            actions.append(self._create_action("ESCALATE_TO_ANALYST", "R9: Specialized investigation for undocumented typology"))

        # R1. Verify before block on weak single signal
        elif single_signal_only and fraud_probability < 0.70:
            triggered_rules.append("R1")
            actions.append(self._create_action("VERIFY_WITH_CUSTOMER", "R1: Single signal with probability <0.70; verify before blocking"))
            missing_evidence.append("Customer confirmation of authorization authenticity")
            # If exposure reaches threshold, also open case per Section 3a
            if fraud_probability >= 0.30 or exposure_usd >= 100.0:
                actions.append(self._create_action("CREATE_CASE", "Section 3a: Internal case opened for pending investigation"))

        # R8. Escalate when uncertain and exposed
        elif verdict == "uncertain" and (exposure_usd > 500.0 or single_signal_only):
            triggered_rules.append("R8")
            actions.append(self._create_action("ESCALATE_TO_ANALYST", f"R8: Uncertain verdict with exposure ${exposure_usd:,.2f} > $500"))
            actions.append(self._create_action("MONITOR_CARD", "R8: Maintain card monitoring while analyst reviews"))
            if fraud_probability >= 0.30:
                actions.append(self._create_action("CREATE_CASE", "Section 3a: Open case for escalated investigation"))

        # High confidence fraud without customer reply yet
        elif fraud_probability >= 0.70:
            actions.append(self._create_action("BLOCK_CARD", f"High confidence fraud (prob={fraud_probability:.2f})", exposure_usd))
            actions.append(self._create_action("CREATE_CASE", "Section 3a: High confidence fraud case"))
            if exposure_usd > 1000.0 or shared_origin:
                should_file_sar = True
                sar_reason = f"Section 3a: Confirmed high-probability fraud exceeding $1,000 threshold (${exposure_usd:,.2f})"
                actions.append(self._create_action("FILE_REPORT", sar_reason))

        # Clear legitimate activity
        elif fraud_probability <= 0.15:
            actions.append(self._create_action("CLOSE_NO_FRAUD", f"Low risk probability ({fraud_probability:.2f}) with corroborating evidence"))

        # Default conservative action
        else:
            actions.append(self._create_action("VERIFY_WITH_CUSTOMER", "R1: Ambiguous activity requires customer verification"))
            actions.append(self._create_action("MONITOR_CARD", "Routine monitoring pending further signals"))

        # R10 Enforcement check: Ensure BLOCK_ALL_CARDS is never applied unless strict conditions hold
        for act in actions:
            if act["action"] == "BLOCK_ALL_CARDS" and not (multiple_cards_confirmed_fraud or credentials_compromised):
                actions.remove(act)
                actions.append(self._create_action("BLOCK_CARD", "R10: Reverted from BLOCK_ALL_CARDS; single card compromise only", exposure_usd))

        # Overall approval route determination
        routes = [act["route"] for act in actions]
        if "L2" in routes:
            overall_route = "L2"
            execution_permission = "APPROVAL_REQUIRED_L2"
        elif "L1" in routes:
            overall_route = "L1"
            execution_permission = "APPROVAL_REQUIRED_L1"
        else:
            overall_route = "auto"
            execution_permission = "AUTHORIZED_FOR_AGENT"

        rationale = f"Evaluated under Fraud Policy v1.0. Triggered rules: {', '.join(triggered_rules) if triggered_rules else 'Baseline'}. " \
                    f"Assessed probability: {fraud_probability:.2f}, Exposure: ${exposure_usd:,.2f}. Highest approval route: {overall_route}."

        return PolicyEvaluationResult(
            triggered_rules=triggered_rules,
            recommended_actions=actions,
            risk_factors=risk_factors,
            missing_evidence=missing_evidence,
            approval_route=overall_route,
            execution_permission=execution_permission,
            rationale=rationale,
            should_file_sar=should_file_sar,
            sar_reason=sar_reason
        )

    def _create_action(self, action: str, reason: str, exposure_usd: float = 0.0) -> Dict[str, Any]:
        """Creates an action dictionary with strict policy routing."""
        act = action.upper().strip()
        exp = float(exposure_usd)

        if act in ["ALLOW_TRANSACTION", "MONITOR_CARD", "MONITOR_CONNECTED_CARDS", 
                   "WARN_CUSTOMER", "VERIFY_WITH_CUSTOMER", "STEP_UP_AUTH", 
                   "GENERATE_REPORT", "CREATE_CASE", "ESCALATE_TO_ANALYST", "CLOSE_NO_FRAUD"]:
            route = "auto"
            exec_status = "AUTHORIZED"
        elif act == "DECLINE_TRANSACTION":
            route = "L1"
            exec_status = "APPROVAL_REQUIRED"
        elif act == "BLOCK_CARD":
            if exp <= 2500.0:
                route = "L1"
                exec_status = "APPROVAL_REQUIRED"
            else:
                route = "L2"
                exec_status = "APPROVAL_REQUIRED"
        elif act in ["BLOCK_ALL_CARDS", "FILE_REPORT"]:
            route = "L2"
            exec_status = "APPROVAL_REQUIRED"
        else:
            route = "L1"
            exec_status = "APPROVAL_REQUIRED"

        return {
            "action": act,
            "route": route,
            "reason": reason,
            "execution_status": exec_status
        }

    def can_auto_execute(self, action: str) -> bool:
        """Returns True if the action has 'auto' approval route and can be executed by the agent."""
        act = action.upper().strip()
        return act in [
            "ALLOW_TRANSACTION", "MONITOR_CARD", "MONITOR_CONNECTED_CARDS", 
            "WARN_CUSTOMER", "VERIFY_WITH_CUSTOMER", "STEP_UP_AUTH", 
            "GENERATE_REPORT", "CREATE_CASE", "ESCALATE_TO_ANALYST", "CLOSE_NO_FRAUD"
        ]

    def get_action_permission(self, action: str, exposure_usd: float = 0.0) -> Dict[str, Any]:
        """Returns route and execution permission status for an action."""
        act_dict = self._create_action(action, "", exposure_usd)
        return {
            "action": act_dict["action"],
            "route": act_dict["route"],
            "execution_status": act_dict["execution_status"],
            "can_auto_execute": self.can_auto_execute(act_dict["action"])
        }

# Global singleton
policy_engine = FraudPolicyEngine()
