"""
Subdomain Finder - Flask Backend
Queries multiple public sources to discover subdomains for a given domain.

Sources included:
  1. crt.sh  – certificate transparency logs
  2. DNS brute-force – resolves entries from a local wordlist

Adding more sources in the future is straightforward:
  - Write a new function that returns a set of subdomains.
  - Call that function inside find_subdomains() and update results.
"""

from flask import Flask, request, jsonify, render_template
import requests
import dns.resolver
import os
import re

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Source 1: crt.sh (certificate transparency logs)
# ---------------------------------------------------------------------------

def get_crtsh_subdomains(domain):
    """Query crt.sh for subdomains via certificate transparency logs."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()
    try:
        resp = requests.get(url, timeout=15)
        if resp.ok:
            data = resp.json()
            for entry in data:
                name = entry.get("name_value", "")
                # Each entry may contain multiple names separated by newlines
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    # Only keep entries that actually belong to the target domain
                    if sub.endswith(f".{domain}") or sub == domain:
                        subdomains.add(sub)
    except Exception:
        pass
    return subdomains

# ---------------------------------------------------------------------------
# Source 2: DNS brute-force with a wordlist
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
# Flask routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Serve the main HTML page."""
    return render_template("index.html")


@app.route("/find", methods=["POST"])
def find_subdomains():
    """
    Accept a JSON payload with a 'domain' key.
    Returns deduplicated, sorted subdomains discovered from all sources.
    Optionally accepts 'bruteforce': true to enable DNS wordlist scanning.
    """
    data = request.get_json(silent=True) or {}
    domain = data.get("domain", "").strip().lower()

    # Basic domain validation
    if not domain:
        return jsonify({"error": "Missing domain"}), 400
    # Domain is already lowercased above, so the regex only needs lowercase chars
    if not re.match(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$", domain):
        return jsonify({"error": "Invalid domain format"}), 400

    enable_bruteforce = bool(data.get("bruteforce", False))

    subdomains = set()

    # --- Source 1: crt.sh ---
    subdomains.update(get_crtsh_subdomains(domain))

    # --- Source 2: DNS brute-force (opt-in) ---
    if enable_bruteforce:
        subdomains.update(dns_bruteforce(domain))

    return jsonify({"subdomains": sorted(subdomains), "count": len(subdomains)})


if __name__ == "__main__":
    app.run(debug=True)
