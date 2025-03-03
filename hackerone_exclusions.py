# hackerone_exclusions.py

"""
Module for handling HackerOne Core Ineligible Findings exclusions for OWASP QuickCheck
"""

# HackerOne Core Ineligible Findings list
HACKERONE_CORE_INELIGIBLE = [
    "Missing security headers (e.g. X-XSS-Protection, X-Content-Type-Options)",
    "SSL/TLS issues (e.g. weak cipher suites, outdated protocols, certificate issues)",
    "Missing rate limits on non-sensitive endpoints",
    "Clickjacking on non-sensitive endpoints",
    "Missing Content-Security-Policy",
    "Username enumeration issues",
    "Missing HttpOnly/Secure cookie flags",
    "Lack of password complexity requirements",
    "Email spoofing with unchanged FROM headers (non-SPF/DKIM/DMARC)",
    "Brute forcing publicly accessible login pages without rate limits",
    "Cross-site Request Forgery (CSRF) without sensitive actions",
    "Vulnerabilities only exploitable in browser extensions",
    "Lack of HTTP Strict Transport Security (HSTS)",
    "Self-XSS without another flaw to leverage it",
    "Tab-nabbing vulnerabilities",
    "Open ports without vulnerable services",
    "Mixed content warnings",
    "Attacks requiring unlikely user interactions",
    "CSP bypass using deprecated directives",
    "DoS using large payload submission",
    "Email verification/email change without confirmation"
]

# Mapping specific OWASP QuickCheck tests to HackerOne Core Ineligible Findings categories
EXCLUSION_MAPPING = {
    "SSL Configuration": ["SSL/TLS issues", "weak cipher suites", "outdated protocols", "certificate issues"],
    "Security Misconfiguration": ["Missing security headers", "Missing Content-Security-Policy", 
                                 "Missing HttpOnly/Secure cookie flags", "Lack of HTTP Strict Transport Security",
                                 "Open ports without vulnerable services"],
    "Access Control": ["Missing rate limits", "Username enumeration", "Brute forcing"],
    "Injection": ["Self-XSS", "Attacks requiring unlikely user interactions"]
}

def should_exclude_test(test_name, exclude_hackerone=False):
    """
    Determine if a test should be excluded based on HackerOne Core Ineligible Findings
    
    Args:
        test_name (str): The name of the security test from OWASP QuickCheck
        exclude_hackerone (bool): Whether to exclude HackerOne Core Ineligible Findings
        
    Returns:
        bool: True if the test should be excluded, False otherwise
    """
    if not exclude_hackerone:
        return False
    
    # Check if the test is directly mapped to a HackerOne exclusion category
    for test, exclusion_categories in EXCLUSION_MAPPING.items():
        if test == test_name and exclusion_categories:
            return True
    
    return False

def get_all_exclusions():
    """
    Returns the full list of HackerOne Core Ineligible Findings as formatted strings
    
    Returns:
        list: All HackerOne Core Ineligible Findings
    """
    return HACKERONE_CORE_INELIGIBLE

def get_excluded_tests():
    """
    Returns a list of all tests that would be excluded if HackerOne exclusions are enabled
    
    Returns:
        list: Test names that would be excluded
    """
    return [test for test in EXCLUSION_MAPPING.keys() if EXCLUSION_MAPPING[test]]