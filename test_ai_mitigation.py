import unittest

from ai_mitigation import generate_mitigations


def make_evidence(**overrides):
    evidence = {
        "session_id": "s1",
        "source_ip": "203.0.113.10",
        "destination_port": 2222,
        "successful_logins": 0,
        "failed_logins": 0,
        "commands": [],
        "reconnaissance_commands": [],
    }
    evidence.update(overrides)
    return evidence


class MitigationTests(unittest.TestCase):
    def test_no_evidence_returns_no_recommendations(self):
        self.assertEqual(generate_mitigations(None), [])

    def test_quiet_session_returns_no_recommendations(self):
        self.assertEqual(generate_mitigations(make_evidence()), [])

    def test_every_recommendation_states_its_observed_reason(self):
        evidence = make_evidence(
            successful_logins=1,
            failed_logins=6,
            commands=["cat /etc/passwd"],
            reconnaissance_commands=["cat /etc/passwd"],
        )
        for item in generate_mitigations(evidence):
            self.assertIn("recommendation", item)
            self.assertTrue(item["reason"].strip())

    def test_successful_login_triggers_access_review(self):
        result = generate_mitigations(make_evidence(successful_logins=2))
        self.assertTrue(any("SSH" in r["recommendation"] for r in result))
        self.assertIn("2 successful", result[0]["reason"])

    def test_few_failed_logins_do_not_trigger_bruteforce_recommendation(self):
        result = generate_mitigations(make_evidence(failed_logins=4))
        self.assertEqual(result, [])

    def test_five_failed_logins_trigger_bruteforce_recommendation(self):
        result = generate_mitigations(make_evidence(failed_logins=5))
        self.assertTrue(any("brute-force" in r["recommendation"] for r in result))

    def test_output_is_capped_at_three_recommendations(self):
        evidence = make_evidence(
            successful_logins=1,
            failed_logins=9,
            commands=["cat /etc/passwd"],
            reconnaissance_commands=["cat /etc/passwd"],
        )
        result = generate_mitigations(evidence)
        self.assertEqual(len(result), 3)

    def test_recommendations_are_advisory_not_actions(self):
        """The module must only return recommendation text; it must not
        expose or perform any enforcement/blocking behaviour."""
        evidence = make_evidence(successful_logins=1)
        result = generate_mitigations(evidence)
        for item in result:
            self.assertEqual(set(item.keys()), {"recommendation", "reason"})


if __name__ == "__main__":
    unittest.main()
