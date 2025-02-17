import requests
import ssl
import socket
import subprocess
import json
import os
import webbrowser
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import openpyxl

class QuickCheckApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("OWASP QuickCheck")

        ttk.Label(self.root, text="Select a document:").pack(pady=5)
        self.documents = self.list_documents()
        self.selected_file = tk.StringVar()
        self.dropdown = ttk.Combobox(self.root, textvariable=self.selected_file, values=self.documents, state="readonly")
        self.dropdown.pack(pady=5)
        self.open_button = ttk.Button(self.root, text="Open Document", command=self.open_document)
        self.open_button.pack(pady=5)

        self.test_button = ttk.Button(self.root, text="Run Security Tests", command=self.run_tests)
        self.test_button.pack(pady=10)

        self.root.mainloop()

    def list_documents(self):
        """Lists available HTML files in the documents folder."""
        doc_path = os.path.join(os.getcwd(), "documents")
        if not os.path.exists(doc_path):
            return []
        return [f for f in os.listdir(doc_path) if f.endswith(".html")]

    def open_document(self):
        """Opens the selected document in the default web browser."""
        selected_file = self.selected_file.get()
        if selected_file:
            file_path = os.path.join(os.getcwd(), "documents", selected_file)
            webbrowser.open(file_path)

    def check_nmap_installed(self):
        """Check if nmap is installed and prompt the user if it is not"""
        try:
            subprocess.run(["nmap", "-V"], capture_output=True, text=True, check=True)
        except FileNotFoundError:
            messagebox.showerror("Nmap Not Found", "Nmap is not installed. Please install it and try again.")
            exit()

    def run_tests(self):
        """Run security tests"""
        self.check_nmap_installed()
        exclusions = self.load_exclusions()

        target_url = simpledialog.askstring("OWASP Top 10 Test", "Enter the website URL to test:")
        if not target_url:
            messagebox.showinfo("OWASP Top 10 Test", "No URL entered. Exiting.")
            return

        custom_header_value = simpledialog.askstring("Custom Header", "Enter the value for the 'Security-Research' header (optional):")
        headers = {"Security-Research": custom_header_value} if custom_header_value else {}

        messagebox.showinfo("OWASP Top 10 Test", "Starting tests. This may take a few moments.")
        results = self.execute_tests(target_url, headers, exclusions)
        result_text = "\n".join(results)

        messagebox.showinfo("OWASP Top 10 Test Results", result_text)

    def load_exclusions(self, file_path="exclusions.txt"):
        """Load exclusions from a file. Tests listed and uncommented will be excluded."""
        exclusions = []
        if os.path.exists(file_path):
            with open(file_path, "r") as file:
                for line in file:
                    line = line.strip()
                    if line and not line.startswith("#"):  # Ignore comments
                        exclusions.append(line)
        return exclusions

    def execute_tests(self, target_url, headers, exclusions):
        """Execute security tests based on exclusions."""
        test_mapping = {
            "Access Control": self.check_access_control,
            "SSL Configuration": self.check_ssl_configuration,
            "Injection": self.test_injection,
            "Security Misconfiguration": self.check_security_misconfigurations,
            "Outdated Components": self.check_outdated_components,
        }

        results = []
        for test_name, test_func in test_mapping.items():
            if test_name not in exclusions:
                if test_name == "Injection":
                    results.append(test_func(target_url, "' OR '1'='1", headers))
                elif test_name == "Access Control":
                    results.append(test_func(target_url, headers))
                else:
                    results.append(test_func(target_url))
        return results

    def check_access_control(self, url, headers):
        try:
            response = requests.get(url, headers=headers, timeout=5)
            return f"[Access Control] Publicly accessible: {url}" if response.status_code == 200 else f"[Access Control] Not accessible: {url}"
        except requests.RequestException as e:
            return f"[Access Control] Error accessing {url}: {e}"

    def check_ssl_configuration(self, url):
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

    def test_injection(self, url, payload, headers):
        try:
            response = requests.get(url, params={"input": payload}, headers=headers, timeout=5)
            return f"[Injection] Vulnerable to injection at {url}" if payload in response.text else f"[Injection] No vulnerability detected at {url}"
        except requests.RequestException as e:
            return f"[Injection] Error testing {url}: {e}"

    def check_security_misconfigurations(self):
        try:
            result = subprocess.run(["nmap", "-p", "1-65535", "127.0.0.1"], capture_output=True, text=True)
            return f"[Security Misconfiguration] Open ports:\n{result.stdout}"
        except FileNotFoundError:
            return "[Security Misconfiguration] Nmap is not installed. Please install nmap."

    def check_outdated_components(self):
        try:
            result = subprocess.run(["safety", "check", "--json"], capture_output=True, text=True)
            vulnerabilities = json.loads(result.stdout)
            if vulnerabilities:
                return f"[Outdated Components] Vulnerabilities found:\n" + "\n".join(
                    f" - {issue['package_name']} {issue['installed_version']}: {issue['description']}" for issue in vulnerabilities)
            else:
                return "[Outdated Components] No vulnerabilities detected."
        except FileNotFoundError:
            return "[Outdated Components] Safety is not installed. Please install safety."

if __name__ == "__main__":
    QuickCheckApp()
