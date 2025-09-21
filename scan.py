import requests
import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import json

def scan_sql_injection(url):
    payload = "' OR '1'='1"
    try:
        response = requests.get(url, params={"input": payload}, timeout=5)
        if "syntax" in response.text.lower() or "mysql" in response.text.lower():
            return True, payload
    except requests.RequestException:
        pass
    return False, None

def scan_xss(url):
    payload = "<script>alert('XSS')</script>"
    try:
        response = requests.get(url, params={"input": payload}, timeout=5)
        if payload in response.text:
            return True, payload
    except requests.RequestException:
        pass
    return False, None

def scan_csrf(url):
    # Simplified CSRF check for illustrative purposes
    try:
        response = requests.get(url, timeout=5)
        if "csrf_token" not in response.text.lower():
            return True, None
    except requests.RequestException:
        pass
    return False, None

def scan_directory_traversal(url):
    payload = "../../etc/passwd"
    try:
        response = requests.get(urljoin(url, payload), timeout=5)
        if "root:x:" in response.text:
            return True, payload
    except requests.RequestException:
        pass
    return False, None

def scan_sensitive_data_exposure(url):
    try:
        response = requests.get(url, timeout=5)
        sensitive_keywords = ["password", "secret", "api_key"]
        for keyword in sensitive_keywords:
            if keyword in response.text.lower():
                return True, None
    except requests.RequestException:
        pass
    return False, None

def scan_subdomains(domain):
    subdomains = [f"test.{domain}", f"secure.{domain}"]
    vulnerable = []
    for subdomain in subdomains:
        url = f"http://{subdomain}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                vulnerable.append(url)
        except requests.RequestException:
            pass
    return vulnerable

def fetch_urls_from_sitemap(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        return [loc.text for loc in soup.find_all('loc')]
    except Exception:
        return []

def generate_report(vulnerabilities, output_file):
    with open(output_file, 'w') as file:
        file.write("Klandestine by BCEVM - Vulnerability Scan Report\n")
        file.write("===========================================\n\n")
        for url, issues in vulnerabilities.items():
            file.write(f"URL: {url}\n")
            if issues:
                file.write("Vulnerabilities Found:\n")
                for issue, payload in issues:
                    file.write(f"  - {issue}")
                    if payload:
                        file.write(f" (Payload: {payload})")
                    file.write("\n")
            else:
                file.write("No vulnerabilities found.\n")
            file.write("\n")

def main():
    target = input("Enter target URL or file with URLs: ").strip()
    urls = []

    if target.startswith("http://") or target.startswith("https://"):
        urls.append(target)
        urls.extend(fetch_urls_from_sitemap(target))
    else:
        try:
            with open(target, 'r') as file:
                urls = [line.strip() for line in file.readlines()]
        except FileNotFoundError:
            print("File not found.")
            return

    vulnerabilities = {}
    for url in urls:
        issues = []
        print(f"Scanning {url}...")
        sql_injection, sql_payload = scan_sql_injection(url)
        if sql_injection:
            issues.append(("SQL Injection", sql_payload))

        xss, xss_payload = scan_xss(url)
        if xss:
            issues.append(("Cross-Site Scripting (XSS)", xss_payload))

        csrf, csrf_payload = scan_csrf(url)
        if csrf:
            issues.append(("Cross-Site Request Forgery (CSRF)", csrf_payload))

        directory_traversal, traversal_payload = scan_directory_traversal(url)
        if directory_traversal:
            issues.append(("Directory Traversal", traversal_payload))

        sensitive_data, sensitive_payload = scan_sensitive_data_exposure(url)
        if sensitive_data:
            issues.append(("Sensitive Data Exposure", sensitive_payload))

        vulnerabilities[url] = issues

    output_file = "klandestine_report.txt"
    generate_report(vulnerabilities, output_file)
    print(f"Scan complete. Report saved to {output_file}")

if __name__ == "__main__":
    main()
