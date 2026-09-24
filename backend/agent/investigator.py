"""
Autonomous Fraud Investigation Agent.
Delegates to the stateful investigation state machine (backend/agent/workflow.py)
and returns compliant answer records per data/README.md.
"""

from typing import Any, Dict, List, Optional
import logging
from backend.agent.workflow import stateful_agent, InvestigationState

logger = logging.getLogger("fraud_agent.investigator")

class FraudInvestigationAgent:
    """
    Autonomous Agent executing stateful fraud investigations.
    """

    def __init__(self, agent=None):
        self.agent = agent or stateful_agent

    def investigate_case(self, case_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes a complete stateful investigation and returns the official answer dictionary.
        """
        state: InvestigationState = self.agent.investigate(case_info)
        return state.to_answer_format()

    def investigate_stateful(self, case_info: Dict[str, Any]) -> InvestigationState:
        """
        Returns the rich InvestigationState object for UI, audit, and deep inspection.
        """
        return self.agent.investigate(case_info)

investigation_agent = FraudInvestigationAgent()
