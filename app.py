"""
Subdomain Finder - Flask Backend
Queries multiple public sources to discover subdomains for a given domain.

Sources included:
  1. crt.sh         – certificate transparency logs
  2. HackerTarget   – free host search API
  3. AlienVault OTX – passive DNS data
  4. URLScan.io     – web scanner results
  5. Web Archive    – Wayback Machine CDX index
  6. DNS brute-force – resolves entries from a local wordlist (opt-in)
"""

from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
import requests
import dns.resolver
import os
import re

app = Flask(__name__)

# Shared HTTP session for connection reuse
_http = requests.Session()
_http.headers.update({"User-Agent": "SubdomainFinder/1.0"})

_REQUEST_TIMEOUT = 15  # seconds


def _valid_subdomain(sub, domain):
    """Return True if *sub* belongs to *domain*."""
    if not sub or not isinstance(sub, str):
        return False
    sub = sub.strip().lstrip("*.").lower()
    if not sub:
        return False
    return sub.endswith(f".{domain}") or sub == domain


# ---------------------------------------------------------------------------
# Source 1: crt.sh (certificate transparency logs)
# ---------------------------------------------------------------------------

def get_crtsh_subdomains(domain):
    """Query crt.sh for subdomains via certificate transparency logs."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()
    try:
        resp = _http.get(url, timeout=_REQUEST_TIMEOUT)
        if resp.ok:
            data = resp.json()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if _valid_subdomain(sub, domain):
                        subdomains.add(sub)
    except Exception:
        pass
    return subdomains


# ---------------------------------------------------------------------------
# Source 2: HackerTarget host search
# ---------------------------------------------------------------------------

def get_hackertarget_subdomains(domain):
    """Query the free HackerTarget host-search API."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    subdomains = set()
    try:
        resp = _http.get(url, timeout=_REQUEST_TIMEOUT)
        if resp.ok and "error" not in resp.text.lower():
            for line in resp.text.splitlines():
                parts = line.split(",")
                if parts:
                    sub = parts[0].strip().lower()
                    if _valid_subdomain(sub, domain):
                        subdomains.add(sub)
    except Exception:
        pass
    return subdomains


# ---------------------------------------------------------------------------
# Source 3: AlienVault OTX passive DNS
# ---------------------------------------------------------------------------

def get_alienvault_subdomains(domain):
    """Retrieve passive-DNS records from AlienVault OTX."""
    url = (
        f"https://otx.alienvault.com/api/v1/indicators/domain/"
        f"{domain}/passive_dns"
    )
    subdomains = set()
    try:
        resp = _http.get(url, timeout=_REQUEST_TIMEOUT)
        if resp.ok:
            data = resp.json()
            for record in data.get("passive_dns", []):
                hostname = record.get("hostname", "").strip().lower()
                if _valid_subdomain(hostname, domain):
                    subdomains.add(hostname)
    except Exception:
        pass
    return subdomains


# ---------------------------------------------------------------------------
# Source 4: URLScan.io
# ---------------------------------------------------------------------------

def get_urlscan_subdomains(domain):
    """Search urlscan.io scan results for subdomains."""
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100"
    subdomains = set()
    try:
        resp = _http.get(url, timeout=_REQUEST_TIMEOUT)
        if resp.ok:
            data = resp.json()
            for result in data.get("results", []):
                page = result.get("page", {})
                hostname = page.get("domain", "").strip().lower()
                if _valid_subdomain(hostname, domain):
                    subdomains.add(hostname)
    except Exception:
        pass
    return subdomains


# ---------------------------------------------------------------------------
# Source 5: Web Archive (Wayback Machine CDX)
# ---------------------------------------------------------------------------

def get_webarchive_subdomains(domain):
    """Query the Wayback Machine CDX API for historical subdomains."""
    url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=200"
    )
    subdomains = set()
    try:
        resp = _http.get(url, timeout=_REQUEST_TIMEOUT)
        if resp.ok:
            rows = resp.json()
            # First row is the header (["original"])
            for row in rows[1:]:
                if row:
                    parsed = urlparse(row[0])
                    hostname = parsed.hostname
                    if hostname and _valid_subdomain(hostname, domain):
                        subdomains.add(hostname.lower())
    except Exception:
        pass
    return subdomains


# ---------------------------------------------------------------------------
# Source 6: DNS brute-force with a wordlist (opt-in)
# ---------------------------------------------------------------------------

def dns_bruteforce(domain, wordlist_path="subdomains.txt"):
    """Resolve potential subdomains from a wordlist file."""
    discovered = set()
    if not os.path.isfile(wordlist_path):
        return discovered
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
    try:
        with open(wordlist_path) as f:
            for line in f:
                sub = line.strip()
                if not sub or sub.startswith("#"):
                    continue
                target = f"{sub}.{domain}"
                try:
                    resolver.resolve(target, "A")
                    discovered.add(target)
                except Exception:
                    continue
    except Exception:
        pass
    return discovered


# ---------------------------------------------------------------------------
# Registry of all available sources
# ---------------------------------------------------------------------------

SOURCES = {
    "crtsh":        {"label": "crt.sh",        "fn": get_crtsh_subdomains},
    "hackertarget": {"label": "HackerTarget",  "fn": get_hackertarget_subdomains},
    "alienvault":   {"label": "AlienVault OTX", "fn": get_alienvault_subdomains},
    "urlscan":      {"label": "URLScan.io",    "fn": get_urlscan_subdomains},
    "webarchive":   {"label": "Web Archive",   "fn": get_webarchive_subdomains},
    "bruteforce":   {"label": "DNS Brute-force", "fn": dns_bruteforce},
}

# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Serve the main HTML page."""
    return render_template("index.html")


@app.route("/sources", methods=["GET"])
def list_sources():
    """Return the list of available sources so the frontend stays in sync."""
    return jsonify({
        key: {"label": val["label"]}
        for key, val in SOURCES.items()
    })


@app.route("/find", methods=["POST"])
def find_subdomains():
    """
    Accept a JSON payload with:
      - 'domain' (required) – target domain
      - 'sources' (optional) – list of source keys to query;
         defaults to all non-bruteforce sources.
    Returns deduplicated, sorted subdomains with per-source attribution.
    """
    data = request.get_json(silent=True) or {}
    domain = data.get("domain", "").strip().lower()

    # Basic domain validation
    if not domain:
        return jsonify({"error": "Missing domain"}), 400
    if not re.match(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$", domain):
        return jsonify({"error": "Invalid domain format"}), 400

    # Determine which sources to query
    requested = data.get("sources")
    if requested and isinstance(requested, list):
        selected = [s for s in requested if s in SOURCES]
    else:
        # Default: everything except brute-force (opt-in)
        selected = [k for k in SOURCES if k != "bruteforce"]

    # Collect subdomains with source attribution
    subdomain_sources = {}  # subdomain -> set of source labels
    for key in selected:
        fn = SOURCES[key]["fn"]
        label = SOURCES[key]["label"]
        found = fn(domain)
        for sub in found:
            subdomain_sources.setdefault(sub, set()).add(label)

    # Build sorted results list
    results = []
    for sub in sorted(subdomain_sources):
        results.append({
            "subdomain": sub,
            "sources": sorted(subdomain_sources[sub]),
        })

    return jsonify({
        "results": results,
        "count": len(results),
    })


if __name__ == "__main__":
    # Enable debug mode only when explicitly requested via environment variable
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug)
