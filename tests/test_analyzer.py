"""Unit tests for IncidentIQ triage engine."""

import unittest
import json

from engine.models import SeverityLevel, IncidentCategory, IncidentAnalysis
from engine.analyzer import RuleBasedAnalyzer
from engine.samples import get_sample_incidents, SAMPLE_INCIDENTS


class TestIncidentAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = RuleBasedAnalyzer()

    def test_empty_input_raises_error(self):
        """Empty input should raise ValueError with helpful message."""
        with self.assertRaises(ValueError) as ctx:
            self.analyzer.analyze("")
        self.assertIn("empty", str(ctx.exception).lower())

        with self.assertRaises(ValueError) as ctx:
            self.analyzer.analyze("   \n\t  ")
        self.assertIn("empty", str(ctx.exception).lower())

    def test_too_brief_input_raises_error(self):
        """Too short input should raise ValueError."""
        with self.assertRaises(ValueError) as ctx:
            self.analyzer.analyze("Error happened")
        self.assertIn("brief", str(ctx.exception).lower())

    def test_all_sample_incidents_analyzed(self):
        """All 8 sample incidents must produce valid, distinct, non-empty analyses."""
        samples = get_sample_incidents()
        self.assertEqual(len(samples), 8)

        categories_seen = set()
        for title, sample in samples.items():
            result = self.analyzer.analyze(sample.description)
            self.assertIsInstance(result, IncidentAnalysis)
            self.assertTrue(result.incident_id.startswith("INC-"))
            self.assertIn(result.severity, [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW])
            self.assertTrue(len(result.likely_root_cause) > 20)
            self.assertTrue(len(result.supporting_evidence) > 0)
            self.assertTrue(len(result.prioritized_troubleshooting_steps) >= 3)
            self.assertTrue(len(result.recommended_next_action) > 10)
            self.assertGreaterEqual(result.confidence_score, 70)

            # Test JSON export
            json_str = result.to_json()
            parsed = json.loads(json_str)
            self.assertEqual(parsed["incident_id"], result.incident_id)
            self.assertEqual(parsed["severity"], result.severity.value)

            categories_seen.add(result.category)

        # Ensure diversity across categories (at least 4 different categories among 8 samples)
        self.assertGreaterEqual(len(categories_seen), 4)

    def test_specific_scenarios(self):
        """Verify scenario-specific diagnosis logic."""
        # Test DB connection pool
        db_sample = get_sample_incidents()["PostgreSQL RDS Connection Pool Exhaustion & Deadlock Contention"]
        res = self.analyzer.analyze(db_sample.description)
        self.assertEqual(res.category, IncidentCategory.DATABASE)
        self.assertEqual(res.severity, SeverityLevel.CRITICAL)
        self.assertIn("pgbouncer", res.likely_root_cause.lower())

        # Test OOMKilled
        oom_sample = get_sample_incidents()["Kubernetes OOMKilled CrashLoopBackOff on Payment Processor"]
        res = self.analyzer.analyze(oom_sample.description)
        self.assertEqual(res.category, IncidentCategory.INFRASTRUCTURE)
        self.assertIn("oomkiller", res.likely_root_cause.lower())

        # Test SSL cert
        ssl_sample = get_sample_incidents()["Expired Production Wildcard SSL/TLS Ingress Certificate"]
        res = self.analyzer.analyze(ssl_sample.description)
        self.assertEqual(res.category, IncidentCategory.SECURITY)
        self.assertIn("expired", res.likely_root_cause.lower())

    def test_generic_fallback_incident(self):
        """Verify arbitrary custom incident input analysis."""
        custom_text = (
            "CRITICAL OUTAGE: All users experiencing HTTP 504 errors when connecting to the API gateway. "
            "Downstream auth service is unresponsive. Error: connection timed out after 30000ms."
        )
        res = self.analyzer.analyze(custom_text)
        self.assertEqual(res.severity, SeverityLevel.CRITICAL)
        self.assertTrue(len(res.prioritized_troubleshooting_steps) > 0)
        self.assertTrue(len(res.supporting_evidence) > 0)


if __name__ == "__main__":
    unittest.main()
