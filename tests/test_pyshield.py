import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests
from pyshield.files import check_virustotal
from pyshield.report import calculate_risk_score, classify_severity, generate_report, save_report


class ReputationTests(unittest.TestCase):
    @patch('pyshield.files.requests.get')
    @patch('pyshield.files.VT_API_KEY', '')
    def test_missing_key_does_not_send_request(self, get):
        self.assertIn('not configured', check_virustotal('abc')['error'])
        get.assert_not_called()

    @patch('pyshield.files.VT_API_KEY', 'test-only-placeholder')
    @patch('pyshield.files.requests.get')
    def test_success_and_timeout_argument(self, get):
        get.return_value = Mock(status_code=200)
        get.return_value.json.return_value = {'data': {'attributes': {
            'last_analysis_stats': {'malicious': 2, 'suspicious': 1, 'undetected': 4}}}}
        self.assertEqual(check_virustotal('abc'), {'malicious': 2, 'suspicious': 1, 'undetected': 4})
        self.assertEqual(get.call_args.kwargs['timeout'], 30)

    @patch('pyshield.files.VT_API_KEY', 'test-only-placeholder')
    @patch('pyshield.files.requests.get', side_effect=requests.Timeout)
    def test_timeout_becomes_error(self, get):
        self.assertEqual(check_virustotal('abc'), {'error': 'API error'})


class ReportTests(unittest.TestCase):
    def test_severity_boundaries(self):
        for score, expected in [(0, 'LOW'), (19, 'LOW'), (20, 'MEDIUM'),
                                (39, 'MEDIUM'), (40, 'HIGH'), (69, 'HIGH'),
                                (70, 'CRITICAL'), (100, 'CRITICAL')]:
            with self.subTest(score=score):
                self.assertEqual(classify_severity(score), expected)

    def test_score_and_cap(self):
        raw = {'processes': [{}], 'ports': [80],
               'files': [{'virustotal': {'malicious': 2, 'suspicious': 1}}]}
        self.assertEqual(calculate_risk_score(raw), 33)
        raw['files'][0]['virustotal']['malicious'] = 20
        self.assertEqual(calculate_risk_score(raw), 100)

    def test_report_round_trip(self):
        raw = {'processes': [], 'ports': [], 'files': [], 'vulnerabilities': []}
        report = generate_report(raw)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            save_report(report, str(path))
            self.assertEqual(json.loads(path.read_text()), report)
            self.assertIn('Severity: LOW', path.with_suffix('.txt').read_text())
        self.assertFalse(report['viruses_found'])


if __name__ == '__main__':
    unittest.main()
