# OWASP QuickCheck v2.0 - Advanced Security Testing Tool

A comprehensive, production-ready security testing tool that automates OWASP Top 10 vulnerability scanning with advanced features including CLI/GUI modes, multi-threaded scanning, and multiple report formats.

## 🚀 What's New in v2.0

### Complete OWASP Top 10 (2021) Coverage
- ✅ **A01:2021** - Broken Access Control
- ✅ **A02:2021** - Cryptographic Failures (Enhanced SSL/TLS analysis)
- ✅ **A03:2021** - Injection (SQL, NoSQL, Command, LDAP, XSS)
- ✅ **A05:2021** - Security Misconfiguration (Headers + Port Scanning)
- ✅ **A06:2021** - Vulnerable and Outdated Components
- ✅ **A07:2021** - Identification and Authentication Failures (NEW)
- ✅ **A08:2021** - Software and Data Integrity Failures (NEW)
- ✅ **A09:2021** - Security Logging and Monitoring Failures (NEW)
- ✅ **A10:2021** - Server-Side Request Forgery (SSRF) (NEW)

### Advanced Features
- 🎯 **Complete XSS Detection** - Reflected, Stored, and DOM-based
- 🎯 **Advanced Injection Testing** - SQL, NoSQL, Command, LDAP with multiple payloads
- 🎯 **API Security Testing** - CORS, GraphQL introspection, API versioning
- 🎯 **HTTP Security Headers Analysis** - Comprehensive checks for all major headers
- 🎯 **CVSS v3.1 Scoring** - Automatic vulnerability severity classification
- 🎯 **Multi-threaded Scanning** - Parallel test execution for faster results
- 🎯 **CLI Mode** - Complete command-line interface for CI/CD integration
- 🎯 **Multiple Report Formats** - JSON, HTML, PDF, Excel
- 🎯 **HackerOne Exclusions** - Built-in filtering for bounty program compliance

## 📋 Features

### Security Testing Capabilities

#### 1. Broken Access Control
- Tests for publicly accessible endpoints
- Status code validation
- Authentication bypass detection

#### 2. Cryptographic Failures
- SSL/TLS certificate validation
- Protocol version detection (flags weak TLS 1.0/1.1/SSLv2/SSLv3)
- Cipher suite analysis
- Certificate chain verification

#### 3. Injection Vulnerabilities
- **SQL Injection**: 8 advanced payloads including UNION, time-based blind
- **NoSQL Injection**: MongoDB/NoSQL bypass payloads
- **Command Injection**: OS command execution detection
- **LDAP Injection**: LDAP query manipulation tests
- **XSS (Cross-Site Scripting)**:
  - Reflected XSS detection
  - DOM-based XSS pattern analysis
  - Multiple payload types (script tags, event handlers, etc.)

#### 4. Security Misconfiguration
- **HTTP Security Headers Check**:
  - Strict-Transport-Security (HSTS)
  - X-Frame-Options (Clickjacking protection)
  - X-Content-Type-Options (MIME sniffing)
  - Content-Security-Policy (CSP)
  - X-XSS-Protection
  - Referrer-Policy
  - Permissions-Policy
  - X-Permitted-Cross-Domain-Policies
- **Port Scanning**: Nmap-based open port detection

#### 5. Vulnerable Components
- Python dependency vulnerability scanning via Safety
- CVE identification
- Version mismatch detection

#### 6. Authentication Failures (NEW)
- Insecure cookie detection (missing Secure/HttpOnly flags)
- Session management analysis
- Password policy validation
- Login form security checks

#### 7. Software/Data Integrity Failures (NEW)
- Subresource Integrity (SRI) validation
- CDN resource signature checking
- Unsigned resource detection

#### 8. Security Logging & Monitoring (NEW)
- Verbose error message detection
- Stack trace exposure
- Debug information leakage
- Error handling analysis

#### 9. Server-Side Request Forgery (SSRF) (NEW)
- Internal IP access testing
- Metadata endpoint detection
- Localhost bypass attempts
- Cloud metadata service checks

#### 10. API Security Testing (NEW)
- CORS misconfiguration detection
- GraphQL introspection testing
- API versioning validation
- REST API endpoint analysis

### Reporting Capabilities

#### JSON Reports
```json
{
  "metadata": {"target_url": "https://example.com"},
  "scan_timestamp": "2025-01-17T12:00:00",
  "summary": {
    "total_tests": 25,
    "critical": 2,
    "high": 5,
    "medium": 3,
    "low": 1
  },
  "results": [...]
}
```

#### HTML Reports
- Interactive, responsive design
- Color-coded severity indicators
- Executive summary dashboard
- Detailed findings table
- Mobile-friendly layout

#### PDF Reports
- Professional layout
- Executive summary
- Detailed findings with CVSS scores
- Severity breakdown
- Remediation guidance

#### Excel Reports
- Structured spreadsheet format
- Color-coded severity levels
- Auto-sized columns
- Timestamp tracking

### CVSS v3.1 Scoring
Automatic vulnerability severity classification:
- **Critical**: 9.0-10.0 (SQL Injection, Command Injection, etc.)
- **High**: 7.0-8.9 (XSS, SSRF, Authentication issues)
- **Medium**: 4.0-6.9 (Security Misconfigurations, CORS)
- **Low**: 0.1-3.9 (Missing headers, informational)

## 🔧 Installation

### Prerequisites

#### Python Dependencies
Install all required Python libraries:

```bash
pip install -r requirements.txt
```

#### External Tools

1. **Nmap** (Required for port scanning)
   - Linux: `sudo apt-get install nmap`
   - macOS: `brew install nmap`
   - Windows: [Download Nmap](https://nmap.org/download.html)

2. **Safety** (Installed via requirements.txt)

### Dependencies List

**Core:**
- requests >= 2.31.0
- openpyxl >= 3.1.2
- safety >= 3.0.0

**Reporting:**
- reportlab >= 4.0.0 (PDF generation)
- jinja2 >= 3.1.2 (HTML templates)
- matplotlib >= 3.8.0 (Charts/graphs)

**API Testing:**
- beautifulsoup4 >= 4.12.0
- lxml >= 5.0.0

**Security Analysis:**
- cryptography >= 41.0.0
- dnspython >= 2.4.0

**CLI Enhancements:**
- colorama >= 0.4.6
- tqdm >= 4.66.0

## 🎮 Usage

### GUI Mode (Default)

Simply run without arguments to launch the graphical interface:

```bash
python3 quickCheck.py
```

**GUI Features:**
- Interactive URL input
- Checkbox for HackerOne exclusions
- Multi-threading toggle (1-20 threads)
- Thread count adjustment
- Documentation viewer
- Results display window
- Multi-format export wizard

### CLI Mode (CI/CD Integration)

Pass command-line arguments for automated scanning:

#### Basic Scan
```bash
python3 quickCheck.py -u https://example.com
```

#### Generate All Report Formats
```bash
python3 quickCheck.py -u https://example.com \
  --json report.json \
  --html report.html \
  --pdf report.pdf \
  --excel report.xlsx
```

#### Advanced Options
```bash
python3 quickCheck.py -u https://example.com \
  --threads 10 \
  --timeout 15 \
  --exclude-hackerone \
  --severity-threshold high \
  --exit-code \
  --header "Authorization: Bearer TOKEN" \
  --header "X-API-Key: KEY123"
```

#### CLI Options Reference

| Option | Description | Default |
|--------|-------------|---------|
| `-u, --url URL` | Target URL to scan (required) | - |
| `--json FILE` | Output JSON report | - |
| `--pdf FILE` | Output PDF report | - |
| `--html FILE` | Output HTML report | - |
| `--excel FILE` | Output Excel report | - |
| `--exclude-hackerone` | Exclude HackerOne Core Ineligible Findings | False |
| `--exclusions FILE` | File containing test exclusions | exclusions.txt |
| `--threads N` | Number of parallel threads | 5 |
| `--timeout SEC` | Request timeout in seconds | 10 |
| `--header KEY:VALUE` | Custom HTTP header (repeatable) | - |
| `--severity-threshold LEVEL` | Min severity (low/medium/high/critical) | - |
| `--exit-code` | Exit with code 1 if vulnerabilities found | False |
| `--verbose, -v` | Verbose output | False |
| `--no-color` | Disable colored output | False |

### CI/CD Integration Examples

#### GitHub Actions
```yaml
- name: Security Scan
  run: |
    python3 quickCheck.py \
      -u ${{ secrets.TARGET_URL }} \
      --json results.json \
      --severity-threshold high \
      --exit-code
```

#### GitLab CI
```yaml
security_scan:
  script:
    - python3 quickCheck.py -u $TARGET_URL --json report.json --exit-code
  artifacts:
    paths:
      - report.json
```

#### Jenkins
```groovy
sh '''
    python3 quickCheck.py \
      -u ${TARGET_URL} \
      --json ${WORKSPACE}/security-report.json \
      --exit-code
'''
```

## 🔐 HackerOne Exclusions

### Usage
Enable via GUI checkbox or CLI flag:
```bash
python3 quickCheck.py -u https://example.com --exclude-hackerone
```

### Excluded Tests
When enabled, the following tests are automatically skipped:
- SSL Configuration (weak ciphers, certificate issues)
- Security Misconfiguration (missing headers, HSTS, cookie flags)
- Access Control (rate limits, username enumeration)
- Injection (Self-XSS, unlikely user interactions)

### Viewing Exclusions
- **GUI**: Click "View HackerOne Exclusions" button
- **CLI**: Check `hackerone_exclusions.py` for full list

### Custom Exclusions
Create or modify `exclusions.txt`:
```
# Tests to exclude (one per line)
SSL Configuration
Security Headers
# SQL Injection  (commented out = not excluded)
```

## 📊 Example Output

### CLI Output
```
======================================================================
   OWASP QuickCheck v2.0 - Advanced Security Scanner
======================================================================
Target: https://example.com
Threads: 5
Timeout: 10s
----------------------------------------------------------------------

Scan Results:

[Broken Access Control] PASS: URL is publicly accessible (Status: 200)
[Cryptographic Failures] PASS: SSL certificate valid for example.com (Protocol: TLSv1.3)
[SQL Injection] PASS: No SQL injection vulnerabilities detected
[XSS] FAIL: Potential reflected XSS detected with payload: <script>alert('XSS')</script>
[Security Headers] FAIL: Missing security headers: Content-Security-Policy (CSP), X-Frame-Options

Summary:
Total Tests: 25
Passed: 18
Failed: 5
Errors: 0
Skipped: 2

Severity Breakdown:
Critical: 0
High: 2
Medium: 3
Low: 0

Elapsed Time: 12.34s

JSON report saved to: report.json
HTML report saved to: report.html
```

### Excel Output Example
| Test Name | Status | Severity | CVSS Score | Message | Timestamp |
|-----------|--------|----------|-----------|---------|-----------|
| SQL Injection | FAIL | Critical | 9.8 | Potential SQL injection detected with payload: ' OR '1'='1 | 2025-01-17T12:00:00 |
| XSS | FAIL | High | 6.1 | Potential reflected XSS detected | 2025-01-17T12:00:05 |
| Security Headers | FAIL | Low | 4.0 | Missing security headers: CSP, HSTS | 2025-01-17T12:00:10 |

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Run all tests
python3 -m pytest test_advanced_features.py -v

# Run specific test class
python3 -m pytest test_advanced_features.py::TestCVSSScorer -v

# Run with coverage
python3 -m pytest test_advanced_features.py --cov=quickCheck
```

Test coverage includes:
- CVSS scoring system
- All security test methods
- Report generation (JSON, HTML, PDF, Excel)
- CLI argument parsing
- Multi-threading functionality
- Integration tests

## 📁 Project Structure

```
owaspQuickCheck/
├── quickCheck.py                   # Main application (1763 lines)
├── hackerone_exclusions.py         # HackerOne exclusions module
├── test_hackerone_exclusions.py    # Unit tests for exclusions
├── test_advanced_features.py       # Comprehensive test suite (NEW)
├── requirements.txt                # Python dependencies
├── exclusions.txt                  # Custom test exclusions
├── readme.md                       # This file
├── LICENSE                         # MIT License
└── documents/                      # Documentation HTML files
    ├── python.html
    ├── curl.html
    ├── dotnetcore.html
    ├── powershell.html
    └── template.html
```

## 🔧 Configuration

### Custom Headers
Add custom headers via CLI:
```bash
python3 quickCheck.py -u https://example.com \
  --header "Security-Research: Security Testing" \
  --header "X-Custom-Header: Value"
```

Or in GUI mode, you'll be prompted for the Security-Research header.

### Thread Configuration
Adjust parallel scanning (1-20 threads):
- GUI: Use the thread count spinner
- CLI: `--threads N`

Recommended:
- Fast scans: 10-15 threads
- Thorough scans: 3-5 threads
- Single-threaded (sequential): 1 thread

### Timeout Settings
Control request timeouts:
```bash
python3 quickCheck.py -u https://slow-site.com --timeout 30
```

## 🚦 Exit Codes (CLI Mode)

| Code | Meaning |
|------|---------|
| 0 | Scan completed successfully, no vulnerabilities OR vulnerabilities found but --exit-code not set |
| 1 | Vulnerabilities found AND --exit-code flag set |

## 🛡️ Security Considerations

This tool is designed for:
- ✅ Authorized security testing
- ✅ Bug bounty programs
- ✅ Internal security audits
- ✅ Development environment testing
- ✅ CI/CD security gates

**Important:**
- Always obtain authorization before testing
- Use responsibly and ethically
- Respect rate limits and robots.txt
- Do not use on production systems without approval

## 🐛 Troubleshooting

### Nmap Not Found
```
Error: Nmap not installed
```
**Solution**: Install nmap (see Installation section)

### Import Errors
```
ImportError: No module named 'reportlab'
```
**Solution**: `pip install -r requirements.txt`

### Permission Denied (Port Scan)
```
Error: Permission denied for port scan
```
**Solution**: Run nmap with appropriate permissions or use non-privileged port range

### SSL Certificate Verification Errors
```
SSLError: certificate verify failed
```
**Solution**: This is expected for sites with invalid certificates (the tool will flag it as a finding)

## 📈 Performance

Typical scan times:
- **Single-threaded**: 2-5 minutes for basic site
- **Multi-threaded (5 threads)**: 30-60 seconds for basic site
- **Multi-threaded (10 threads)**: 15-30 seconds for basic site

Factors affecting speed:
- Target response time
- Number of tests enabled
- Network latency
- Thread count
- Exclusions applied

## 🤝 Contributing

Contributions are welcome! Areas for improvement:
- Additional OWASP Top 10 test cases
- New payload databases
- Additional report formats
- Enhanced API testing
- Web dashboard interface

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- OWASP Foundation for security standards
- HackerOne for Core Ineligible Findings list
- Python security community

## 📞 Support

For issues, feature requests, or questions:
- Open an issue on GitHub
- Check existing documentation
- Review test cases for usage examples

## 🔄 Version History

### v2.0.0 (2025-01-17)
- ✨ Complete OWASP Top 10 (2021) coverage
- ✨ Advanced injection testing (SQL, NoSQL, Command, LDAP, XSS)
- ✨ API security testing module
- ✨ CVSS v3.1 scoring system
- ✨ CLI mode for CI/CD integration
- ✨ Multi-format reporting (JSON, HTML, PDF, Excel)
- ✨ Multi-threaded scanning
- ✨ Authentication and session testing
- ✨ Software integrity checks
- ✨ Security logging analysis
- ✨ SSRF detection
- ✨ Comprehensive HTTP security headers check
- ✨ Enhanced SSL/TLS analysis
- 🧪 Comprehensive test suite

### v1.0.0 (2024)
- Initial release
- Basic OWASP Top 5 coverage
- GUI interface
- Excel reporting
- HackerOne exclusions

---

**Made with ❤️ for the security community**
