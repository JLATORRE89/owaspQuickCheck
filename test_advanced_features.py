#!/usr/bin/env python3
"""
Comprehensive test suite for OWASP QuickCheck advanced features
"""

import unittest
import sys
import os
from unittest.mock import Mock, patch, MagicMock
import json

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from quickCheck import (
    SecurityScanner,
    ScanResult,
    CVSSScorer,
    ReportGenerator
)


class TestCVSSScorer(unittest.TestCase):
    """Test CVSS scoring system"""

    def test_get_severity_none(self):
        self.assertEqual(CVSSScorer.get_severity(0.0), "None")

    def test_get_severity_low(self):
        self.assertEqual(CVSSScorer.get_severity(2.5), "Low")

    def test_get_severity_medium(self):
        self.assertEqual(CVSSScorer.get_severity(5.0), "Medium")

    def test_get_severity_high(self):
        self.assertEqual(CVSSScorer.get_severity(7.5), "High")

    def test_get_severity_critical(self):
        self.assertEqual(CVSSScorer.get_severity(9.5), "Critical")

    def test_get_score_xss(self):
        self.assertEqual(CVSSScorer.get_score("XSS"), 6.1)

    def test_get_score_sql_injection(self):
        self.assertEqual(CVSSScorer.get_score("SQL Injection"), 9.8)

    def test_get_score_unknown(self):
        self.assertEqual(CVSSScorer.get_score("Unknown Vuln"), 5.0)


class TestScanResult(unittest.TestCase):
    """Test ScanResult data structure"""

    def test_scan_result_creation(self):
        result = ScanResult(
            "Test XSS",
            "FAIL",
            "XSS vulnerability detected",
            "High",
            6.1,
            {"payload": "<script>alert('XSS')</script>"}
        )

        self.assertEqual(result.test_name, "Test XSS")
        self.assertEqual(result.status, "FAIL")
        self.assertEqual(result.message, "XSS vulnerability detected")
        self.assertEqual(result.severity, "High")
        self.assertEqual(result.cvss_score, 6.1)
        self.assertEqual(result.details["payload"], "<script>alert('XSS')</script>")

    def test_scan_result_to_dict(self):
        result = ScanResult("Test", "PASS", "No issues", "Info")
        result_dict = result.to_dict()

        self.assertIn("test_name", result_dict)
        self.assertIn("status", result_dict)
        self.assertIn("message", result_dict)
        self.assertIn("severity", result_dict)
        self.assertIn("cvss_score", result_dict)
        self.assertIn("timestamp", result_dict)

    def test_scan_result_str(self):
        result = ScanResult("Test", "PASS", "Success")
        result_str = str(result)

        self.assertIn("Test", result_str)
        self.assertIn("PASS", result_str)
        self.assertIn("Success", result_str)


class TestSecurityScanner(unittest.TestCase):
    """Test SecurityScanner functionality"""

    def setUp(self):
        self.scanner = SecurityScanner("https://example.com", timeout=5, max_workers=2)

    @patch('requests.Session.get')
    def test_check_access_control_success(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        result = self.scanner.check_access_control()

        self.assertEqual(result.test_name, "Broken Access Control")
        self.assertEqual(result.status, "PASS")
        self.assertIn("publicly accessible", result.message.lower())

    @patch('requests.Session.get')
    def test_check_access_control_error(self, mock_get):
        mock_get.side_effect = Exception("Connection error")

        result = self.scanner.check_access_control()

        self.assertEqual(result.status, "ERROR")

    @patch('socket.create_connection')
    def test_check_ssl_configuration_valid(self, mock_socket):
        # Mock SSL socket
        mock_ssl_socket = MagicMock()
        mock_ssl_socket.getpeercert.return_value = {
            'subject': ((('commonName', 'example.com'),),),
            'issuer': ((('organizationName', 'Test CA'),),)
        }
        mock_ssl_socket.cipher.return_value = ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
        mock_ssl_socket.version.return_value = 'TLSv1.3'

        with patch('ssl.SSLContext.wrap_socket', return_value=mock_ssl_socket):
            result = self.scanner.check_ssl_configuration()

        self.assertEqual(result.test_name, "Cryptographic Failures")
        self.assertEqual(result.status, "PASS")

    @patch('requests.Session.get')
    def test_test_sql_injection_detected(self, mock_get):
        mock_response = Mock()
        mock_response.text = "MySQL syntax error near"
        mock_get.return_value = mock_response

        results = self.scanner.test_sql_injection()

        self.assertTrue(any(r.status == "FAIL" for r in results))

    @patch('requests.Session.get')
    def test_test_sql_injection_not_detected(self, mock_get):
        mock_response = Mock()
        mock_response.text = "Normal response"
        mock_get.return_value = mock_response

        results = self.scanner.test_sql_injection()

        self.assertTrue(all(r.status == "PASS" for r in results))

    @patch('requests.Session.get')
    def test_test_xss_reflected(self, mock_get):
        payload = "<script>alert('XSS')</script>"
        mock_response = Mock()
        mock_response.text = f"Search results for: {payload}"
        mock_get.return_value = mock_response

        results = self.scanner.test_xss()

        self.assertTrue(any(r.status == "FAIL" for r in results))

    @patch('requests.Session.get')
    def test_check_security_headers_missing(self, mock_get):
        mock_response = Mock()
        mock_response.headers = {}  # No security headers
        mock_get.return_value = mock_response

        results = self.scanner.check_security_headers()

        self.assertTrue(any(r.status == "FAIL" for r in results))

    @patch('requests.Session.get')
    def test_check_security_headers_present(self, mock_get):
        mock_response = Mock()
        mock_response.headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
            "X-Permitted-Cross-Domain-Policies": "none"
        }
        mock_get.return_value = mock_response

        results = self.scanner.check_security_headers()

        self.assertTrue(any(r.status == "PASS" for r in results))

    @patch('requests.Session.get')
    def test_test_ssrf_detected(self, mock_get):
        mock_response = Mock()
        mock_response.text = "169.254.169.254 metadata"
        mock_get.return_value = mock_response

        results = self.scanner.test_ssrf()

        self.assertTrue(any(r.status == "FAIL" for r in results))

    @patch('requests.Session.options')
    def test_api_security_cors_misconfiguration(self, mock_options):
        mock_response = Mock()
        mock_response.headers = {'Access-Control-Allow-Origin': '*'}
        mock_options.return_value = mock_response

        results = self.scanner.test_api_security()

        self.assertTrue(any("CORS" in r.test_name and r.status == "FAIL" for r in results))

    @patch('subprocess.run')
    def test_check_outdated_components(self, mock_run):
        mock_result = Mock()
        mock_result.stdout = json.dumps([
            {
                "package_name": "requests",
                "installed_version": "2.0.0",
                "vulnerability": "CVE-2023-1234"
            }
        ])
        mock_run.return_value = mock_result

        result = self.scanner.check_outdated_components()

        self.assertEqual(result.status, "FAIL")
        self.assertIn("vulnerable components", result.message.lower())

    def test_run_all_tests_with_exclusions(self):
        scanner = SecurityScanner("https://example.com", timeout=1, max_workers=1)

        # Mock all network calls to avoid actual requests
        with patch.object(scanner, 'check_access_control') as mock_access, \
             patch.object(scanner, 'check_ssl_configuration') as mock_ssl, \
             patch.object(scanner, 'test_sql_injection') as mock_sql, \
             patch.object(scanner, 'test_xss') as mock_xss:

            mock_access.return_value = ScanResult("Access Control", "PASS", "OK")
            mock_ssl.return_value = ScanResult("SSL", "PASS", "OK")
            mock_sql.return_value = [ScanResult("SQL Injection", "PASS", "OK")]
            mock_xss.return_value = [ScanResult("XSS", "PASS", "OK")]

            results = scanner.run_all_tests(
                exclusions=["SQL Injection"],
                exclude_hackerone=False,
                use_threading=False
            )

            # Check that SQL Injection was skipped
            sql_results = [r for r in results if "SQL Injection" in r.test_name]
            if sql_results:
                self.assertEqual(sql_results[0].status, "SKIPPED")


class TestReportGenerator(unittest.TestCase):
    """Test report generation functionality"""

    def setUp(self):
        self.results = [
            ScanResult("Test 1", "PASS", "OK", "Info", 0.0),
            ScanResult("Test 2", "FAIL", "Vulnerability found", "High", 8.0),
            ScanResult("Test 3", "ERROR", "Error occurred", "Info", 0.0),
        ]

    def test_generate_summary(self):
        summary = ReportGenerator._generate_summary(self.results)

        self.assertEqual(summary["total_tests"], 3)
        self.assertEqual(summary["passed"], 1)
        self.assertEqual(summary["failed"], 1)
        self.assertEqual(summary["errors"], 1)
        self.assertEqual(summary["high"], 1)

    def test_generate_json_report(self):
        output_file = "/tmp/test_report.json"
        metadata = {"target_url": "https://example.com"}

        ReportGenerator.generate_json(self.results, output_file, metadata)

        self.assertTrue(os.path.exists(output_file))

        with open(output_file, 'r') as f:
            report = json.load(f)

        self.assertIn("metadata", report)
        self.assertIn("results", report)
        self.assertIn("summary", report)
        self.assertEqual(len(report["results"]), 3)

        # Cleanup
        os.remove(output_file)

    def test_generate_html_report(self):
        output_file = "/tmp/test_report.html"
        metadata = {"target_url": "https://example.com"}

        try:
            ReportGenerator.generate_html(self.results, output_file, metadata)
            self.assertTrue(os.path.exists(output_file))

            with open(output_file, 'r') as f:
                content = f.read()

            self.assertIn("OWASP QuickCheck", content)
            self.assertIn("example.com", content)
            self.assertIn("Test 1", content)

            # Cleanup
            os.remove(output_file)
        except ImportError:
            self.skipTest("jinja2 not installed")

    def test_generate_excel_report(self):
        output_file = "/tmp/test_report.xlsx"
        metadata = {"target_url": "https://example.com"}

        try:
            ReportGenerator.generate_excel(self.results, output_file, metadata)
            self.assertTrue(os.path.exists(output_file))

            # Cleanup
            os.remove(output_file)
        except ImportError:
            self.skipTest("openpyxl not installed")

    def test_generate_pdf_report(self):
        output_file = "/tmp/test_report.pdf"
        metadata = {"target_url": "https://example.com"}

        try:
            ReportGenerator.generate_pdf(self.results, output_file, metadata)
            self.assertTrue(os.path.exists(output_file))

            # Cleanup
            os.remove(output_file)
        except ImportError:
            self.skipTest("reportlab not installed")


class TestIntegration(unittest.TestCase):
    """Integration tests for complete workflows"""

    @patch('requests.Session.get')
    @patch('requests.Session.options')
    def test_full_scan_workflow(self, mock_options, mock_get):
        """Test a complete scan workflow"""
        # Setup mocks
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Normal response"
        mock_response.headers = {
            "Strict-Transport-Security": "max-age=31536000"
        }
        mock_response.cookies = []
        mock_get.return_value = mock_response
        mock_options.return_value = mock_response

        # Create scanner and run tests
        scanner = SecurityScanner("https://example.com", timeout=1, max_workers=1)

        # Run a subset of tests to avoid SSL/subprocess issues in tests
        with patch.object(scanner, 'check_ssl_configuration') as mock_ssl, \
             patch.object(scanner, 'check_security_misconfigurations') as mock_ports, \
             patch.object(scanner, 'check_outdated_components') as mock_components:

            mock_ssl.return_value = ScanResult("SSL", "PASS", "OK")
            mock_ports.return_value = ScanResult("Ports", "PASS", "OK")
            mock_components.return_value = ScanResult("Components", "PASS", "OK")

            results = scanner.run_all_tests(use_threading=False)

        # Verify results
        self.assertGreater(len(results), 0)
        self.assertTrue(all(isinstance(r, ScanResult) for r in results))

        # Test report generation
        output_file = "/tmp/integration_test_report.json"
        ReportGenerator.generate_json(results, output_file, {"target_url": "https://example.com"})

        self.assertTrue(os.path.exists(output_file))

        # Cleanup
        os.remove(output_file)


if __name__ == "__main__":
    # Run tests with verbose output
    unittest.main(verbosity=2)
