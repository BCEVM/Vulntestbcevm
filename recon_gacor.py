#!/usr/bin/env python3
"""
recon_gacor.py
Safe reconnaissance tool:
- Subdomain enumeration (wordlist-based + common prefixes)
- DNS resolve check (A records)
- Simple crawling (respects robots.txt)
- Extract URLs (absolute)
- Save results to urls.txt and results.json

Usage:
    python3 recon_gacor.py example.com

Dependencies:
    pip install requests dnspython beautifulsoup4
"""

import sys
import time
import json
import socket
import concurrent.futures
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup
import dns.resolver
import urllib.robotparser

# Config
USER_AGENT = "ReconGacor/1.0 (+https://github.com/bcevm)"
THREADS = 12
REQUEST_TIMEOUT = 8
RATE_DELAY = 0.1  # seconds between requests to same host
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "api", "dev", "staging", "test",
    "blog", "shop", "m", "mobile", "admin", "portal", "smtp"
]
CUSTOM_WORDLIST = [
    # Add more words if you want — keep short by default
    "dev", "stage", "uat", "beta", "dashboard", "secure", "static"
]


def make_headers():
    return {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}


def resolve_host(hostname):
    """Return list of IPv4 addresses or empty list"""
    ips = set()
    try:
        answers = dns.resolver.resolve(hostname, "A", lifetime=5)
        for r in answers:
            ips.add(r.to_text())
    except Exception:
        pass
    return list(ips)


def probe_subdomains(domain, extra_words=None):
    """Try common subdomains and return live ones (resolved)"""
    words = list(COMMON_SUBDOMAINS)
    if extra_words:
        words += extra_words
    found = {}
    for w in words:
        candidate = f"{w}.{domain}"
        ips = resolve_host(candidate)
        if ips:
            found[candidate] = ips
    # Always include root domain as well
    root_ips = resolve_host(domain)
    if root_ips:
        found[domain] = root_ips
    return found


def fetch_robots_txt(base_url):
    """Return parsed robots parser or None"""
    try:
        rp = urllib.robotparser.RobotFileParser()
        robots_url = urljoin(base_url, "/robots.txt")
        rp.set_url(robots_url)
        rp.read()
        return rp
    except Exception:
        return None


def get_page_links(url, base_netloc):
    """Fetch page and extract absolute links (only http(s))."""
    links = set()
    try:
        r = requests.get(url, headers=make_headers(), timeout=REQUEST_TIMEOUT, allow_redirects=True)
        content_type = r.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            return links
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a.get("href").strip()
            if href.startswith("javascript:") or href.startswith("mailto:"):
                continue
            abs_url = urljoin(r.url, href)
            parsed = urlparse(abs_url)
            if parsed.scheme in ("http", "https"):
                # keep everything; callers can filter by netloc
                links.add(abs_url)
    except Exception:
        pass
    return links


def crawl_host(start_url, max_pages=200):
    """Crawl starting at start_url, respect robots if available."""
    parsed = urlparse(start_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    rp = fetch_robots_txt(base)
    to_visit = [start_url]
    seen = set()
    results = set()
    last_request_time = 0

    while to_visit and len(seen) < max_pages:
        url = to_visit.pop(0)
        if url in seen:
            continue
        parsed_url = urlparse(url)
        # robots check
        if rp and not rp.can_fetch(USER_AGENT, url):
            seen.add(url)
            continue

        # rate limit per host
        elapsed = time.time() - last_request_time
        if elapsed < RATE_DELAY:
            time.sleep(RATE_DELAY - elapsed)

        links = get_page_links(url, parsed.netloc)
        last_request_time = time.time()
        seen.add(url)
        results.add(url)

        # enqueue same-host links
        for L in links:
            p = urlparse(L)
            if p.netloc == parsed.netloc and L not in seen:
                to_visit.append(L)

    return results


def run_recon(domain_or_url):
    # Normalize to URL
    parsed = urlparse(domain_or_url)
    if parsed.scheme == "":
        base_url = "https://" + domain_or_url
    else:
        base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else domain_or_url

    domain = urlparse(base_url).netloc
    print(f"[+] Target base: {base_url}")
    print("[*] Enumerating subdomains (common wordlist)...")
    subdomains = probe_subdomains(domain, extra_words=CUSTOM_WORDLIST)
    if not subdomains:
        print("[-] No subdomains resolved from the basic list. You can provide a larger wordlist.")
    else:
        print(f"[+] Found {len(subdomains)} live host(s).")

    # Prepare start URLs
    start_urls = []
    for host in subdomains:
        # prefer https
        start_urls.append(f"https://{host}")
        start_urls.append(f"http://{host}")

    # de-dup
    start_urls = list(dict.fromkeys(start_urls))

    # Crawl hosts concurrently
    all_urls = set()
    print("[*] Crawling discovered hosts (this can take a while)...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as exe:
        futures = {exe.submit(crawl_host, u, 200): u for u in start_urls}
        for f in concurrent.futures.as_completed(futures):
            u = futures[f]
            try:
                res = f.result()
                print(f"[+] Crawled {u} -> {len(res)} urls")
                all_urls.update(res)
            except Exception as e:
                print(f"[-] Error crawling {u}: {e}")

    # Make sure base_url pages are included
    all_urls.add(base_url)
    print(f"[+] Total unique URLs found: {len(all_urls)}")

    # Save to files
    urls_list = sorted(all_urls)
    with open("urls.txt", "w", encoding="utf-8") as fh:
        for u in urls_list:
            fh.write(u + "\n")
    with open("results.json", "w", encoding="utf-8") as fh:
        json.dump({"target": domain_or_url, "found": urls_list, "subdomains": subdomains}, fh, indent=2)

    print("[*] Saved urls.txt and results.json")
    return {"urls": urls_list, "subdomains": subdomains}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 recon_gacor.py <domain_or_url>")
        sys.exit(1)
    target = sys.argv[1].strip()
    out = run_recon(target)
