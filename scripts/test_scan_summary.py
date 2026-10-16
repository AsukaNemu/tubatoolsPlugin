import json
import tempfile
import unittest
from pathlib import Path

from scan_summary import build_summary


class ScanSummaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.write('collect.exit', '0')
        self.write('clamav.exit', '0')
        self.write('clamav.log', 'Scanned files: 2\nInfected files: 0\n')
        self.write('yara.exit', '0')
        self.write('yara.txt', '')
        self.write('virustotal.exit', '0')
        self.write('virustotal.json', json.dumps({'status': 'skip'}))

    def write(self, name, value):
        (self.root / name).write_text(value, encoding='utf-8')

    def test_completed_scan_with_explicit_optional_skip_can_verify(self):
        self.assertEqual(build_summary(self.root)['label'], 'verified')

    def test_missing_results_do_not_verify(self):
        with tempfile.TemporaryDirectory() as empty:
            self.assertEqual(build_summary(empty)['label'], 'needs-review')

    def test_scanner_error_is_not_a_clean_scan(self):
        self.write('clamav.exit', '2')
        self.assertEqual(build_summary(self.root)['label'], 'needs-review')

    def test_zero_files_is_not_a_clean_scan(self):
        self.write('clamav.log', 'Scanned files: 0\n')
        self.assertEqual(build_summary(self.root)['label'], 'needs-review')

    def test_partial_collection_is_not_a_complete_scan(self):
        self.write('collect.exit', '1')
        self.assertEqual(build_summary(self.root)['label'], 'needs-review')

    def test_malformed_virustotal_output_is_not_a_skip(self):
        self.write('virustotal.json', 'Checking file...\n{}')
        self.assertEqual(build_summary(self.root)['label'], 'needs-review')

    def test_unknown_virustotal_result_requires_review(self):
        self.write('virustotal.json', json.dumps({'status': 'unknown'}))
        self.assertEqual(build_summary(self.root)['label'], 'needs-review')

    def test_threat_cannot_verify(self):
        self.write('clamav.exit', '1')
        self.assertEqual(build_summary(self.root)['label'], 'malware-detected')

    def test_yara_error_is_distinct_from_a_rule_match(self):
        self.write('yara.exit', '1')
        self.assertEqual(build_summary(self.root)['checks']['YARA']['status'], 'error')
        self.write('yara.exit', '0')
        self.write('yara.txt', 'Suspicious test.exe\n')
        self.assertEqual(build_summary(self.root)['checks']['YARA']['status'], 'warn')

    def test_only_valid_virustotal_pass_results_can_verify(self):
        for files, label in [([], 'needs-review'), ([{'status': 'unknown'}], 'needs-review'),
                             ([{'status': 'pass', 'positives': 0, 'total': 70}], 'verified')]:
            self.write('virustotal.json', json.dumps({'status': 'pass', 'files': files}))
            self.assertEqual(build_summary(self.root)['label'], label)


if __name__ == '__main__':
    unittest.main()
