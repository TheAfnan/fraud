"""
Unit tests for backend/policy/engine.py
Verifies rules R1 through R10, approval routes (auto, L1, L2), and SAR triggers.
"""

import unittest
from backend.policy.engine import FraudPolicyEngine

class TestFraudPolicyEngine(unittest.TestCase):
    def setUp(self):
        self.engine = FraudPolicyEngine()

    def test_r1_verify_before_block_on_weak_signal(self):
        # R1: Single signal with prob < 0.70 -> VERIFY_WITH_CUSTOMER or STEP_UP_AUTH, no BLOCK_CARD
        res = self.engine.evaluate(
            fraud_probability=0.55,
            exposure_usd=300.0,
            single_signal_only=True
        )
        self.assertIn("R1", res.triggered_rules)
        action_names = [a["action"] for a in res.recommended_actions]
        self.assertIn("VERIFY_WITH_CUSTOMER", action_names)
        self.assertNotIn("BLOCK_CARD", action_names)
        self.assertEqual(res.approval_route, "auto")

    def test_r2_customer_denies_low_exposure(self):
        # R2: Customer denies, exposure <= $1,000 -> BLOCK_CARD (L1), CREATE_CASE (auto), NO SAR
        res = self.engine.evaluate(
            fraud_probability=0.90,
            exposure_usd=400.0,
            customer_response="denied"
        )
        self.assertIn("R2", res.triggered_rules)
        action_names = [a["action"] for a in res.recommended_actions]
        self.assertIn("BLOCK_CARD", action_names)
        self.assertIn("CREATE_CASE", action_names)
        self.assertFalse(res.should_file_sar)
        self.assertEqual(res.approval_route, "L1")

    def test_r2_customer_denies_high_exposure(self):
        # R2: Customer denies, exposure > $1,000 -> BLOCK_CARD (L2 if > 2500, L1 if <= 2500), FILE_REPORT (L2)
        res = self.engine.evaluate(
            fraud_probability=0.95,
            exposure_usd=3200.0,
            customer_response="denied"
        )
        self.assertIn("R2", res.triggered_rules)
        self.assertTrue(res.should_file_sar)
        action_names = [a["action"] for a in res.recommended_actions]
        self.assertIn("FILE_REPORT", action_names)
        self.assertIn("BLOCK_CARD", action_names)
        self.assertEqual(res.approval_route, "L2")

    def test_r3_customer_confirms(self):
        # R3: Customer confirms -> CLOSE_NO_FRAUD
        res = self.engine.evaluate(
            fraud_probability=0.10,
            exposure_usd=0.0,
            customer_response="confirmed"
        )
        self.assertIn("R3", res.triggered_rules)
        action_names = [a["action"] for a in res.recommended_actions]
        self.assertEqual(action_names, ["CLOSE_NO_FRAUD"])
        self.assertEqual(res.approval_route, "auto")

    def test_r4_no_reply_24h(self):
        # R4: No reply >= 24h -> MONITOR_CARD, DECLINE_TRANSACTION
        res = self.engine.evaluate(
            fraud_probability=0.40,
            exposure_usd=600.0,
            customer_response="no_reply",
            no_reply_hours=24.5
        )
        self.assertIn("R4", res.triggered_rules)
        action_names = [a["action"] for a in res.recommended_actions]
        self.assertIn("MONITOR_CARD", action_names)
        self.assertIn("DECLINE_TRANSACTION", action_names)
        self.assertIn("ESCALATE_TO_ANALYST", action_names)  # exposure > 500

    def test_r5_card_testing(self):
        # R5: micro-auths + larger cleared purchase > 100 -> BLOCK_CARD
        res = self.engine.evaluate(
            fraud_probability=0.85,
            exposure_usd=250.0,
            is_card_testing=True,
            cleared_purchase_over_100=True
        )
        self.assertIn("R5", res.triggered_rules)
        action_names = [a["action"] for a in res.recommended_actions]
        self.assertIn("BLOCK_CARD", action_names)

    def test_r6_shared_origin(self):
        # R6: Shared origin -> CREATE_CASE, FILE_REPORT, MONITOR_CONNECTED_CARDS
        res = self.engine.evaluate(
            fraud_probability=0.88,
            exposure_usd=1200.0,
            shared_origin=True,
            shared_element_name="DeviceProfile-D892",
            connected_cards_count=3
        )
        self.assertIn("R6", res.triggered_rules)
        self.assertTrue(res.should_file_sar)
        action_names = [a["action"] for a in res.recommended_actions]
        self.assertIn("CREATE_CASE", action_names)
        self.assertIn("FILE_REPORT", action_names)
        self.assertIn("MONITOR_CONNECTED_CARDS", action_names)

    def test_r7_disputed_recurring(self):
        # R7: Disputed recurring charge -> CREATE_CASE, VERIFY_WITH_CUSTOMER, WARN_CUSTOMER, no BLOCK
        res = self.engine.evaluate(
            fraud_probability=0.20,
            exposure_usd=49.0,
            is_recurring_legit=True
        )
        self.assertIn("R7", res.triggered_rules)
        action_names = [a["action"] for a in res.recommended_actions]
        self.assertIn("CREATE_CASE", action_names)
        self.assertIn("VERIFY_WITH_CUSTOMER", action_names)
        self.assertIn("WARN_CUSTOMER", action_names)
        self.assertNotIn("BLOCK_CARD", action_names)

    def test_r8_escalate_uncertain_exposed(self):
        # R8: Uncertain and exposure > 500 -> ESCALATE_TO_ANALYST
        res = self.engine.evaluate(
            fraud_probability=0.50,
            exposure_usd=750.0,
            verdict="uncertain"
        )
        self.assertIn("R8", res.triggered_rules)
        action_names = [a["action"] for a in res.recommended_actions]
        self.assertIn("ESCALATE_TO_ANALYST", action_names)

    def test_r9_undocumented_coordinated(self):
        # R9: Undocumented coordinated abuse -> CREATE_CASE, FILE_REPORT, ESCALATE_TO_ANALYST
        res = self.engine.evaluate(
            fraud_probability=0.80,
            exposure_usd=1500.0,
            is_undocumented_coordinated=True
        )
        self.assertIn("R9", res.triggered_rules)
        self.assertTrue(res.should_file_sar)
        action_names = [a["action"] for a in res.recommended_actions]
        self.assertIn("CREATE_CASE", action_names)
        self.assertIn("FILE_REPORT", action_names)
        self.assertIn("ESCALATE_TO_ANALYST", action_names)

    def test_r10_never_block_all_cards_without_proof(self):
        # R10: If somehow BLOCK_ALL_CARDS was suggested without 2+ compromised cards, revert to BLOCK_CARD
        res = self.engine.evaluate(
            fraud_probability=0.95,
            exposure_usd=5000.0,
            customer_response="denied",
            multiple_cards_confirmed_fraud=False,
            credentials_compromised=False
        )
        action_names = [a["action"] for a in res.recommended_actions]
        self.assertNotIn("BLOCK_ALL_CARDS", action_names)
        self.assertIn("BLOCK_CARD", action_names)

if __name__ == "__main__":
    unittest.main()
