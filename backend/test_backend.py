"""
Tests for the AccessGuard AI backend.
Run with:  python test_backend.py
Covers: health, employees, scan, what-if simulation, audit trail (hash chain),
AI explanation, the 6-module / 1-tool-each AWS architecture, and zero-trust remediation.
"""

import sys
import os
import unittest
import json

# Add backend and root directories to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from backend.app import app

class TestAccessGuardBackend(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.client.testing = True

    def test_01_health_check(self):
        """GET /api/health is online and lists the 6 AWS tools."""
        response = self.client.get('/api/health')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "online")
        self.assertIn("timestamp", data)
        self.assertIn("aws_tools_active", data)
        self.assertEqual(data["aws_tools_active"], [
            "Amazon AppFlow", "Amazon S3", "Amazon SageMaker",
            "Amazon Bedrock", "Amazon EventBridge", "AWS CloudTrail"
        ])

    def test_02_get_employees(self):
        """Test GET /api/employees returns enriched list and summary KPIs."""
        response = self.client.get('/api/employees')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("summary", data)
        self.assertIn("employees", data)
        self.assertGreater(len(data["employees"]), 0)
        
        first_emp = data["employees"][0]
        self.assertIn("risk_score", first_emp)
        self.assertIn("risk_tier", first_emp)
        self.assertIn("findings", first_emp)
        self.assertIn("consented_roles", first_emp)
        self.assertIn("usage_patterns", first_emp)
        self.assertIn("anomaly_score", first_emp["usage_patterns"])

    def test_03_get_employee_by_id(self):
        """Test GET /api/employees/EMP-001 returns Bob Martinez details with AWS telemetry."""
        response = self.client.get('/api/employees/EMP-001')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("employee", data)
        self.assertEqual(data["employee"]["id"], "EMP-001")
        self.assertEqual(data["employee"]["name"], "Bob Martinez")
        self.assertIn("aws_telemetry", data)

    def test_04_scan_endpoint(self):
        """Test POST /api/scan triggers on-demand audit and flags high exposure."""
        response = self.client.post('/api/scan')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "success")
        self.assertGreater(data["scanned_identities"], 0)
        self.assertIn("critical_alerts", data)
        self.assertIn("aws_pipeline", data)
        self.assertEqual(data["aws_pipeline"]["alerting"], "Amazon EventBridge")

    def test_05_simulate_endpoint(self):
        """Test POST /api/simulate models access change without modifying live data."""
        payload = {
            "employee_id": "EMP-001",
            "revoke_admin": True,
            "resolve_drift": True,
            "enable_mfa": True,
            "proposed_role": "Junior Marketing Associate"
        }
        response = self.client.post('/api/simulate', 
                                    data=json.dumps(payload),
                                    content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("baseline", data)
        self.assertIn("simulated", data)
        self.assertLess(data["simulated"]["risk_score"], data["baseline"]["risk_score"])
        self.assertGreater(data["risk_reduction_points"], 0)
        self.assertIn("changes", data)

    def test_05b_simulate_does_not_change_live_data(self):
        """The what-if simulator must never modify the stored employee."""
        before = json.loads(self.client.get('/api/employees/EMP-001').data)["employee"]["risk_score"]
        self.client.post('/api/simulate', data=json.dumps({"employee_id": "EMP-001", "revoke_admin": True}),
                         content_type='application/json')
        after = json.loads(self.client.get('/api/employees/EMP-001').data)["employee"]["risk_score"]
        self.assertEqual(before, after)

    def test_05c_simulate_requires_employee(self):
        """Missing or unknown employee returns a clear error."""
        r = self.client.post('/api/simulate', data=json.dumps({}), content_type='application/json')
        self.assertEqual(r.status_code, 400)
        r = self.client.post('/api/simulate', data=json.dumps({"employee_id": "EMP-999"}),
                             content_type='application/json')
        self.assertEqual(r.status_code, 404)

    def test_06_drift_history(self):
        """Test GET /api/drift-history returns timeline records."""
        response = self.client.get('/api/drift-history')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("timeline", data)
        self.assertGreater(len(data["timeline"]), 0)
        self.assertIn("hash", data["timeline"][0])

    def test_06b_audit_trail_is_intact(self):
        """GET /api/audit/verify confirms the hash chain has not been broken."""
        data = json.loads(self.client.get('/api/audit/verify').data)
        self.assertTrue(data["intact"])
        self.assertIsNone(data["broken_at"])

    def test_07_ai_explain(self):
        """POST /api/ai-explain returns an early warning and an action plan."""
        payload = {"employee_id": "EMP-001"}
        response = self.client.post('/api/ai-explain',
                                    data=json.dumps(payload),
                                    content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("executive_summary", data)
        self.assertIn("early_warning", data)
        self.assertIn("recommended_action_plan", data)
        self.assertIn("aws_orchestration", data)
        self.assertIn("EARLY WARNING", data["early_warning"])

    def test_07b_ai_explain_clean_employee(self):
        """A low-risk employee gets NO false alarm."""
        r = self.client.post('/api/ai-explain', data=json.dumps({"employee_id": "EMP-004"}),
                             content_type='application/json')
        data = json.loads(r.data)
        self.assertNotIn("EARLY WARNING", data["early_warning"])

    def test_08_aws_architecture(self):
        """GET /api/aws-architecture returns the 6 modules with exactly ONE tool each."""
        response = self.client.get('/api/aws-architecture')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("problem_statement", data)
        self.assertIn("mvp", data)
        self.assertIn("expected_outcome", data)
        self.assertEqual(len(data["modules"]), 6)

        expected = {
            "SaaS Data Ingestion & Integration": "Amazon AppFlow",
            "Data Storage & Log Analytics": "Amazon S3",
            "AI Permission Drift & Anomaly Detection": "Amazon SageMaker",
            "Explainable AI & Remediation Recommendation": "Amazon Bedrock",
            "Alerting & Automated Remediation": "Amazon EventBridge",
            "Security, Identity & Audit": "AWS CloudTrail",
        }
        actual = {m["module"]: m["tool"] for m in data["modules"]}
        self.assertEqual(actual, expected)

    def test_09_remediate_endpoint(self):
        """POST /api/remediate removes risky access, lowers risk, and writes an audit entry."""
        before = json.loads(self.client.get('/api/employees/EMP-002').data)["employee"]["risk_score"]
        payload = {"employee_id": "EMP-002", "action": "full_least_privilege"}
        response = self.client.post('/api/remediate',
                                    data=json.dumps(payload),
                                    content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "success")
        self.assertGreater(data["risk_reduction_points"], 0)
        self.assertLess(data["new_risk"], before)
        self.assertGreater(len(data["changes"]), 0)
        self.assertIn("aws_execution", data)
        self.assertIn("audit_log_id", data)

        # the change is real, and the new audit entry keeps the chain intact
        after = json.loads(self.client.get('/api/employees/EMP-002').data)["employee"]["risk_score"]
        self.assertEqual(after, data["new_risk"])
        self.assertTrue(json.loads(self.client.get('/api/audit/verify').data)["intact"])

    def test_09b_remediate_rejects_bad_action(self):
        """An unknown action is rejected instead of silently doing nothing."""
        r = self.client.post('/api/remediate', data=json.dumps({"employee_id": "EMP-001", "action": "nope"}),
                             content_type='application/json')
        self.assertEqual(r.status_code, 400)

    def test_10_audit_chain_detects_tampering(self):
        """Editing an old audit entry must be detected."""
        import backend.app as backend
        orig = backend.audit_log[-1]["details"]
        try:
            backend.audit_log[-1]["details"] = "edited after the fact"
            data = json.loads(self.client.get('/api/audit/verify').data)
            self.assertFalse(data["intact"])
            self.assertEqual(data["broken_at"], backend.audit_log[-1]["id"])
        finally:
            backend.audit_log[-1]["details"] = orig

    def test_11_saas_integrations_catalog(self):
        """GET /api/saas-integrations returns supported SaaS apps with roles."""
        response = self.client.get('/api/saas-integrations')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "success")
        self.assertGreaterEqual(data["total_integrations"], 8)
        self.assertIn("integrations", data)
        names = [item["name"] for item in data["integrations"]]
        self.assertIn("Salesforce", names)
        self.assertIn("AWS IAM", names)
        self.assertIn("GitHub Enterprise", names)
        self.assertIn("Snowflake", names)
        self.assertIn("Okta", names)

    def test_12_add_employee_endpoint(self):
        """POST /api/employees allows adding new user data with custom SaaS permissions."""
        payload = {
            "name": "Jordan Cole",
            "email": "jordan.cole@example.com",
            "department": "Engineering",
            "title": "Cloud DevOps Contractor",
            "mfa_enabled": False,
            "last_login_days": 130,
            "drift_detected": True,
            "drift_summary": "Retained AWS Root Administrator privileges post infrastructure migration.",
            "saas_accounts": ["AWS IAM", "GitHub"],
            "permissions": [
                {"service": "AWS IAM", "privilege": "AdministratorAccess (Root Equivalent)", "is_admin": True, "sensitive": True},
                {"service": "GitHub", "privilege": "Organization Owner", "is_admin": True, "sensitive": True}
            ]
        }
        response = self.client.post('/api/employees',
                                    data=json.dumps(payload),
                                    content_type='application/json')
        self.assertEqual(response.status_code, 201)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "success")
        new_emp = data["employee"]
        self.assertEqual(new_emp["name"], "Jordan Cole")
        self.assertEqual(new_emp["risk_tier"], "CRITICAL")
        self.assertGreaterEqual(new_emp["risk_score"], 80)
        self.assertTrue(new_emp["drift_detected"])
        self.assertFalse(new_emp["mfa_enabled"])

        # Confirm new employee appears in GET /api/employees list
        list_res = self.client.get('/api/employees')
        emp_list = json.loads(list_res.data)["employees"]
        found = any(e["name"] == "Jordan Cole" for e in emp_list)
        self.assertTrue(found)

    def test_13_add_employee_validation(self):
        """POST /api/employees returns 400 when required fields are missing."""
        response = self.client.post('/api/employees',
                                    data=json.dumps({"department": "Marketing"}),
                                    content_type='application/json')
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn("error", data)

    def test_14_auth_login_and_me(self):
        """POST /api/auth/login authenticates administrator and GET /api/auth/me validates session."""
        login_res = self.client.post('/api/auth/login',
                                     data=json.dumps({"demo_role": "admin"}),
                                     content_type='application/json')
        self.assertEqual(login_res.status_code, 200)
        login_data = json.loads(login_res.data)
        self.assertEqual(login_data["status"], "success")
        token = login_data["token"]
        self.assertIn("Alex Vance", login_data["user"]["name"])

        # Check /api/auth/me with bearer token
        me_res = self.client.get('/api/auth/me', headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(me_res.status_code, 200)
        me_data = json.loads(me_res.data)
        self.assertTrue(me_data["authenticated"])
        self.assertEqual(me_data["user"]["email"], "admin@accessguard.ai")

    def test_15_reset_employees_endpoint(self):
        """POST /api/employees/reset restores sample permission records."""
        response = self.client.post('/api/employees/reset')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "success")
        
        # Verify baseline count is 6
        list_res = self.client.get('/api/employees')
        total = json.loads(list_res.data)["summary"]["total_identities"]
        self.assertEqual(total, 6)

if __name__ == '__main__':
    unittest.main()
