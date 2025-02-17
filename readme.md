# OWASP Top 10 Automation Tool

This Python application automates security testing for web applications based on the OWASP Top 10 vulnerabilities. It provides a GUI interface to prompt for a target URL, performs automated checks, and optionally saves the results to an Excel file. Additionally, it includes a **Documentation Viewer** to access relevant HTML documentation files directly from the interface.

## Features

1. **Broken Access Control**
   - Checks for publicly accessible endpoints.

2. **Cryptographic Failures**
   - Verifies SSL/TLS configuration.

3. **Injection**
   - Performs basic input validation and injection tests.

4. **Security Misconfigurations**
   - Scans for open ports using `nmap`.

5. **Vulnerable and Outdated Components**
   - Detects known vulnerabilities in dependencies using `safety`.

6. **Excel Report**
   - Saves the test results into a structured Excel file.

7. **Documentation Viewer**
   - Lists available HTML documentation files from the `documents` folder.
   - Allows users to select and open documentation in their default web browser.

## Prerequisites

### Python Dependencies
Install the required Python libraries:

```bash
pip install -r requirements.txt
```

### External Tools
1. **Nmap**
   - Install `nmap` for open port scanning.
     - Linux: `sudo apt-get install nmap`
     - macOS: `brew install nmap`
     - Windows: [Download Nmap](https://nmap.org/download.html)

2. **Safety**
   - Install `safety` for dependency vulnerability checking.
   - Installed via `requirements.txt`.

## Usage

For Linux:
1. Run the script:
   ```bash
   python3 quickCheck.py
   ```
For Windows:
1. Run the script:
   ```
   python quickCheck.py
   ```

2. Enter the target URL when prompted.

3. The application performs the checks and displays the results in a pop-up window.

4. Optionally save the results to an Excel file.

5. Use the **Documentation Viewer** to open HTML files from the `documents` folder.

## Error Handling
- If `nmap` is not installed, the application will display an error message and exit.

## Output
The results are displayed in a GUI window and can be exported to an Excel file named `OWASP_Top_10_Results.xlsx`.

## Example Excel Output
| Test Name                      | Result                                                                 |
|--------------------------------|------------------------------------------------------------------------|
| Access Control                 | Publicly accessible: https://example.com                              |
| SSL                            | SSL certificate valid for example.com                                 |
| Injection                      | No vulnerability detected at https://example.com                     |
| Security Misconfiguration      | Open ports: ...                                                       |
| Outdated Components            | Vulnerabilities found: ...                                            |

## License
This project is licensed under the MIT License.
