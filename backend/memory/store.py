"""
Case Memory Store for Graph-backed Fraud Investigation.
Interfaces with TigerGraph's ClosedCase vertices and stores active/closed investigation memory.
"""

from typing import Any, Dict, List, Optional
import logging
from backend.tigergraph.gateway import graph_gateway

logger = logging.getLogger("fraud_agent.memory")

class CaseMemoryStore:
    """
    Manages historical closed cases and newly investigated cases in graph memory.
    """

    def __init__(self):
        self.gateway = graph_gateway
        self.local_case_memory: Dict[str, Dict[str, Any]] = {}

    def retrieve_similar_cases(self,
                               pattern: str,
                               min_exposure: float = 0.0,
                               max_exposure: float = 0.0,
                               max_results: int = 3) -> List[Dict[str, Any]]:
        """
        Retrieves matching historical closed cases from TigerGraph.
        """
        try:
            cases = self.gateway.find_similar_cases(
                pattern=pattern,
                min_exposure=min_exposure,
                max_exposure=max_exposure,
                max_results=max_results
            )
            return cases
        except Exception as e:
            logger.warning(f"Failed to query similar cases from graph: {e}")
            return []

    def record_case_in_memory(self, case_id: str, case_data: Dict[str, Any]) -> None:
        """
        Records completed investigation into working memory and writes to graph.
        """
        self.local_case_memory[case_id] = case_data

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        return self.local_case_memory.get(case_id)

    def write_to_tigergraph(self, case_id: str, customer_id: str, card_id: str,
                            verdict: str, fraud_prob: float, pattern: str,
                            pattern_desc: str, exposure: float, summary: str,
                            sar_filed: bool, flagged_txn_id: str) -> Dict[str, Any]:
        """
        Writes completed case back to TigerGraph graph memory.
        """
        return self.gateway.write_case_to_graph(
            case_id=case_id,
            customer_id=customer_id,
            card_id=card_id,
            verdict=verdict,
            fraud_prob=fraud_prob,
            pattern=pattern,
            pattern_desc=pattern_desc,
            exposure=exposure,
            summary=summary,
            sar_filed=sar_filed,
            flagged_txn_id=flagged_txn_id
        )

case_memory = CaseMemoryStore()
