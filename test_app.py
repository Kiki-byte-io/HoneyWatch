import unittest
import json
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "dashboard"))

from app import app

class HoneyWatchTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_index_page(self):
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'HONEYWATCH', response.data)

    def test_api_summary(self):
        response = self.app.get('/api/dashboard/summary')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('total_sessions', data)
        self.assertIn('unique_ips', data)
        self.assertIn('bot_assessment', data)

    def test_api_intelligence(self):
        response = self.app.get('/api/intelligence')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('summary', data)
        self.assertIn('mitigations', data)
        self.assertIn('automation', data)

    def test_api_attacks(self):
        response = self.app.get('/api/attacks')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('events', data)

    def test_api_sessions(self):
        response = self.app.get('/api/sessions')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('sessions', data)

    def test_api_ips(self):
        response = self.app.get('/api/ips')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('ips', data)

    def test_api_commands(self):
        response = self.app.get('/api/commands')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('commands', data)

    def test_api_credentials(self):
        response = self.app.get('/api/credentials')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('usernames', data)
        self.assertNotIn('passwords', data)  # Password field must NOT be exposed

    def test_api_timeline(self):
        response = self.app.get('/api/timeline')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('timeline', data)

    def test_api_classifier(self):
        response = self.app.get('/api/classifier')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('automation_score', data)

    def test_api_report_pdf(self):
        response = self.app.get('/api/report/pdf?range=all')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, 'application/pdf')
        self.assertGreater(len(response.data), 1000)

    def test_api_export_csv(self):
        response = self.app.get('/api/export/csv')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, 'text/csv')

if __name__ == '__main__':
    unittest.main()
