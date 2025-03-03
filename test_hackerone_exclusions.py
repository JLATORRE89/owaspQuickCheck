# test_hackerone_exclusions.py

import unittest
from hackerone_exclusions import should_exclude_check, HACKERONE_CORE_INELIGIBLE

class TestHackerOneExclusions(unittest.TestCase):
    def test_exclusion_disabled(self):
        """Test that checks are not excluded when the feature is disabled"""
        excluded_check = "Test for Missing Security Headers"
        self.assertFalse(should_exclude_check(excluded_check, exclude_hackerone=False))
        
    def test_security_headers_exclusion(self):
        """Test that security header checks are excluded"""
        excluded_check = "Test for Missing Security Headers"
        self.assertTrue(should_exclude_check(excluded_check, exclude_hackerone=True))
        
    def test_ssl_tls_exclusion(self):
        """Test that SSL/TLS issues are excluded"""
        excluded_check = "Check for weak cipher suites"
        self.assertTrue(should_exclude_check(excluded_check, exclude_hackerone=True))
        
    def test_csrf_exclusion(self):
        """Test that CSRF checks are excluded"""
        excluded_check = "Check for Cross-site Request Forgery vulnerabilities"
        self.assertTrue(should_exclude_check(excluded_check, exclude_hackerone=True))
        
    def test_non_excluded_check(self):
        """Test that non-excluded checks are not affected"""
        non_excluded_check = "Test for SQL Injection"
        self.assertFalse(should_exclude_check(non_excluded_check, exclude_hackerone=True))
        
    def test_case_insensitivity(self):
        """Test that exclusions are case-insensitive"""
        excluded_check = "check for MISSING SECURITY HEADERS"
        self.assertTrue(should_exclude_check(excluded_check, exclude_hackerone=True))
        
if __name__ == "__main__":
    unittest.main()