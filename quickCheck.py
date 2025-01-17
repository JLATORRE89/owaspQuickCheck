import requests
import ssl
import socket
import subprocess
import json
from urllib.parse import urlparse
import tkinter as tk
from tkinter import messagebox, simpledialog
import openpyxl
import os

def check_nmap_installed():
    """Check if nmap is installed and prompt the user if it is not"""
    try:
        subprocess.run(["nmap", "-V"], capture_output=True, text=True, check=True)
    except FileNotFoundError:
        root = tk.Tk()
        root.withdraw()  # Hide the main window
        messagebox.showerror("Nmap Not Found", "Nmap is not installed. Please install it and try again.")
        exit()

def check_access_control(url, headers):
    """Check for publicly accessible endpoints"""
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            return f"[Access Control] Publicly accessible: {url}"
        else:
            return f"[Access Control] Not accessible: {url}"
    except requests.RequestException as e:
        return f"[Access Control] Error accessing {url}: {e}"

def check_ssl_configuration(url):
    """Check SSL/TLS configuration"""
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    port = 443

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return f"[SSL] SSL certificate valid for {hostname}"
    except ssl.SSLError as e:
        return f"[SSL] SSL Error for {hostname}: {e}"
    except Exception as e:
        return f"[SSL] Error connecting to {hostname}: {e}"

def test_injection(url, payload, headers):
    """Basic test for injection vulnerabilities"""
    try:
        response = requests.get(url, params={"input": payload}, headers=headers, timeout=5)
        if payload in response.text:
            return f"[Injection] Vulnerable to injection at {url}"
        else:
            return f"[Injection] No vulnerability detected at {url}"
    except requests.RequestException as e:
        return f"[Injection] Error testing {url}: {e}"

def check_security_misconfigurations():
    """Scan for open ports (requires nmap installed)"""
    try:
        result = subprocess.run(["nmap", "-p", "1-65535", "127.0.0.1"], capture_output=True, text=True)
        return f"[Security Misconfiguration] Open ports:\n{result.stdout}"
    except FileNotFoundError:
        return "[Security Misconfiguration] Nmap is not installed. Please install nmap."

def check_outdated_components():
    """Check for outdated dependencies"""
    try:
        result = subprocess.run(["safety", "check", "--json"], capture_output=True, text=True)
        vulnerabilities = json.loads(result.stdout)
        if vulnerabilities:
            issues = "\n".join(
                f" - {issue['package_name']} {issue['installed_version']}: {issue['description']}" for issue in vulnerabilities
            )
            return f"[Outdated Components] Vulnerabilities found:\n{issues}"
        else:
            return "[Outdated Components] No vulnerabilities detected."
    except FileNotFoundError:
        return "[Outdated Components] Safety is not installed. Please install safety."

def find_unreferenced_files(target_url):
    """Find and analyze unreferenced files that might contain sensitive information"""
    suspicious_extensions = [".old", ".bak", ".inc", ".src", ".cache"]
    results = []
    try:
        for ext in suspicious_extensions:
            test_url = f"{target_url.rstrip('/')}/{ext}"
            response = requests.head(test_url, timeout=5)
            if response.status_code == 200:
                results.append(f"[Unreferenced Files] Accessible file: {test_url}")
    except requests.RequestException as e:
        results.append(f"[Unreferenced Files] Error checking files: {e}")

    return "\n".join(results) if results else "[Unreferenced Files] No suspicious files found."

def write_results_to_excel(results, file_path="OWASP_Top_10_Results.xlsx"):
    """Write test results to an Excel template"""
    try:
        workbook = openpyxl.Workbook()
        sheet = workbook.active
        sheet.title = "OWASP Results"

        # Headers
        sheet.append(["Test Name", "Result"])

        for result in results:
            test_name, test_result = result.split("]", 1)
            test_name = test_name.strip("[")
            sheet.append([test_name, test_result.strip()])

        workbook.save(file_path)
        messagebox.showinfo("Excel Export", f"Results saved to {file_path}")
    except Exception as e:
        messagebox.showerror("Excel Export", f"Error saving results to Excel: {e}")

def run_tests(target_url, headers):
    results = []

    # Broken Access Control
    results.append(check_access_control(target_url, headers))

    # Cryptographic Failures
    results.append(check_ssl_configuration(target_url))

    # Injection
    results.append(test_injection(target_url, "' OR '1'='1", headers))

    # Security Misconfiguration
    results.append(check_security_misconfigurations())

    # Vulnerable and Outdated Components
    results.append(check_outdated_components())

    # Unreferenced Files
    results.append(find_unreferenced_files(target_url))

    return results

def main():
    check_nmap_installed()

    root = tk.Tk()
    root.withdraw()  # Hide the main window

    target_url = simpledialog.askstring("OWASP Top 10 Test", "Enter the website URL to test:")

    if not target_url:
        messagebox.showinfo("OWASP Top 10 Test", "No URL entered. Exiting.")
        return

    custom_header_value = simpledialog.askstring("Custom Header", "Enter the value for the 'Security-Research' header (optional):")
    headers = {"Security-Research": custom_header_value} if custom_header_value else {}

    messagebox.showinfo("OWASP Top 10 Test", "Starting tests. This may take a few moments.")

    results = run_tests(target_url, headers)
    result_text = "\n".join(results)

    messagebox.showinfo("OWASP Top 10 Test Results", result_text)

    save_to_excel = messagebox.askyesno("Save Results", "Would you like to save the results to an Excel file?")
    if save_to_excel:
        write_results_to_excel(results)

if __name__ == "__main__":
    main()
