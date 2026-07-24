import re
import sys
import math
import json
import socket
import ssl
import argparse
import ipaddress
from datetime import datetime
from urllib.parse import urlparse, unquote
import urllib.request
import urllib.error
from html.parser import HTMLParser

KNOWN_BRANDS = [
    "paypal", "apple", "google", "microsoft", "facebook", "amazon", "linkedin",
    "twitter", "instagram", "dropbox", "yahoo", "ebay", "wellsfargo", "chase",
    "bankofamerica", "citibank", "hsbc", "barclays", "netflix", "spotify",
    "adobe", "salesforce", "slack", "zoom", "twitch", "reddit", "tumblr",
    "pinterest", "outlook", "office365", "icloud", "coinbase", "binance", "steam"
]

SUSPICIOUS_TLDS = {
    ".zip", ".review", ".country", ".kim", ".cricket", ".work", ".party", ".gq",
    ".ml", ".tk", ".cf", ".ga", ".xyz", ".top", ".club", ".online", ".site",
    ".website", ".space", ".tech", ".link", ".click", ".download", ".host",
    ".info", ".press", ".pro", ".store", ".vip", ".win", ".world", ".zone",
    ".bid", ".loan", ".mov"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "cutt.ly", "shorturl.at", "tiny.cc", "mcaf.ee",
    "soo.gd", "v.gd", "cli.gs", "tr.im", "u.to", "x.co", "rebrand.ly"
}

SUSPICIOUS_KEYWORDS = [
    "login", "secure", "account", "update", "verify", "confirm", "password",
    "banking", "billing", "paypal", "appleid", "signin", "reset", "verification",
    "credentials", "access", "identity", "suspicious", "fraud", "scam",
    "phishing", "webscr", "invoice", "suspend", "unlock", "alert", "urgent",
    "limited", "recovery"
]

def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)
    prev_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev_row[j] + 1, curr[j - 1] + 1, prev_row[j - 1] + cost)
        prev_row = curr
    return prev_row[-1]

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    length = len(s)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())

class SimpleHTMLInspector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title = ""
        self.in_title = False
        self.meta_description = ""
        self.forms = []
        self.current_form = None
        self.password_inputs = 0
        self.hidden_iframes = 0
        self.obfuscated_scripts = 0
        self.in_script = False
        self.script_content = []
        self.links = []
        self.favicon_url = ""

    def handle_starttag(self, tag, attrs):
        attr_dict = {k.lower(): v for k, v in attrs if k and v}
        tag = tag.lower()
        if tag == "title":
            self.in_title = True
        elif tag == "meta":
            if attr_dict.get("name", "").lower() == "description":
                self.meta_description = attr_dict.get("content", "")
        elif tag == "link":
            rel = attr_dict.get("rel", "").lower()
            if "icon" in rel and not self.favicon_url:
                self.favicon_url = attr_dict.get("href", "")
        elif tag == "a" and "href" in attr_dict:
            self.links.append(attr_dict["href"])
        elif tag == "form":
            self.current_form = {"action": attr_dict.get("action", ""), "method": attr_dict.get("method", "get").upper()}
            self.forms.append(self.current_form)
        elif tag == "input":
            if attr_dict.get("type", "").lower() == "password":
                self.password_inputs += 1
        elif tag == "iframe":
            style = attr_dict.get("style", "").replace(" ", "").lower()
            w = attr_dict.get("width", "")
            h = attr_dict.get("height", "")
            if "display:none" in style or "visibility:hidden" in style or w in ("0", "1") or h in ("0", "1"):
                self.hidden_iframes += 1
        elif tag == "script":
            self.in_script = True
            self.script_content = []

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "title":
            self.in_title = False
        elif tag == "script":
            self.in_script = False
            full_code = "".join(self.script_content)
            if re.search(r"eval\s*\(|unescape\s*\(|fromCharCode|document\.write\s*\(\s*unescape", full_code):
                self.obfuscated_scripts += 1

    def handle_data(self, data):
        if self.in_title:
            self.title += data
        elif self.in_script:
            self.script_content.append(data)

class Finding:
    def __init__(self, points: int, reason: str, severity: str = "low"):
        self.points = points
        self.reason = reason
        self.severity = severity

    def to_dict(self):
        return {
            "points": self.points,
            "reason": self.reason,
            "severity": self.severity
        }

class RiskReport:
    def __init__(self, url: str):
        self.url = url
        self.findings = []
        self.details = {
            "dns": {},
            "ssl": {},
            "http": {},
            "content": {},
            "security_headers": {}
        }

    @property
    def score(self) -> int:
        return min(100, sum(f.points for f in self.findings))

    @property
    def verdict(self) -> str:
        s = self.score
        if s >= 70:
            return "HIGH RISK - likely phishing"
        if s >= 40:
            return "SUSPICIOUS - potential threat"
        if s >= 15:
            return "LOW RISK - minor red flags"
        return "LIKELY SAFE - no major indicators"

    def add(self, points: int, reason: str, severity: str = "low"):
        self.findings.append(Finding(points, reason, severity))

    def to_dict(self):
        return {
            "url": self.url,
            "score": self.score,
            "verdict": self.verdict,
            "findings": [f.to_dict() for f in self.findings],
            "details": self.details
        }

    def print_report(self):
        bar_len = 30
        filled = int(bar_len * self.score / 100)
        bar = "=" * filled + "-" * (bar_len - filled)

        print("=" * 65)
        print("                DEEP WEBSITE & PHISHING THREAT REPORT")
        print("=" * 65)
        print(f"Target URL : {self.url}")
        print(f"Risk Score : [{bar}] {self.score}/100")
        print(f"Verdict    : {self.verdict}")
        print("-" * 65)

        if self.details.get("dns", {}).get("ip"):
            print(f"Resolved IP : {self.details['dns']['ip']} (PTR: {self.details['dns'].get('hostname', 'N/A')})")
        if self.details.get("ssl", {}).get("subject"):
            print(f"SSL Cert    : Issued to {self.details['ssl']['subject']} by {self.details['ssl'].get('issuer', 'N/A')}")
            print(f"SSL Expiry  : {self.details['ssl'].get('not_after', 'N/A')} ({self.details['ssl'].get('days_remaining', 0)} days remaining)")
        if self.details.get("http", {}).get("status"):
            print(f"HTTP Status : {self.details['http']['status']} | Server: {self.details['http'].get('server', 'N/A')}")
        if self.details.get("content", {}).get("title"):
            print(f"Page Title  : {self.details['content']['title']}")

        print("-" * 65)
        print("RISK INDICATORS DETECTED:")
        if not self.findings:
            print("  [+] No threat indicators detected.")
        else:
            ordered = sorted(self.findings, key=lambda f: f.points, reverse=True)
            for f in ordered:
                tag = {"high": "[HIGH]", "medium": "[MED ]", "low": "[LOW ]"}[f.severity]
                print(f"  {tag} +{f.points:>2} pts | {f.reason}")
        print("=" * 65)

class DeepURLAnalyzer:
    def __init__(self, url: str):
        if not re.match(r"^\w+://", url):
            url = "http://" + url
        self.raw = url
        self.parsed = urlparse(url)
        self.host = (self.parsed.hostname or "").lower()
        self.port = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)

    def analyze_lexical(self, report: RiskReport):
        self._check_ip_host(report)
        self._check_https(report)
        self._check_at_symbol(report)
        self._check_length(report)
        self._check_hyphens_and_subdomains(report)
        self._check_shortener(report)
        self._check_suspicious_tld(report)
        self._check_keywords(report)
        self._check_typosquatting(report)
        self._check_entropy(report)
        self._check_port(report)
        self._check_punycode(report)

    def _check_ip_host(self, r):
        try:
            ip = ipaddress.ip_address(self.host)
            r.add(25, f"Hostname is a raw IP address ({self.host}) instead of a domain name", "high")
            if ip.is_private:
                r.add(15, f"Hostname resolves to a private IP address range ({self.host})", "medium")
        except ValueError:
            pass

    def _check_https(self, r):
        if self.parsed.scheme != "https":
            r.add(10, "Connection scheme is unencrypted HTTP (no TLS protection)", "medium")

    def _check_at_symbol(self, r):
        if "@" in self.raw:
            r.add(20, "URL contains '@' symbol - browser ignores content before '@' and routes to the target host", "high")

    def _check_length(self, r):
        n = len(self.raw)
        if n > 100:
            r.add(10, f"Unusually long URL structure ({n} characters) - frequently used to obscure destination", "medium")
        elif n > 75:
            r.add(5, f"Long URL structure ({n} characters)", "low")

    def _check_hyphens_and_subdomains(self, r):
        hyphens = self.host.count("-")
        if hyphens >= 3:
            r.add(10, f"Domain contains excessive hyphens ({hyphens}) - typical in brand impersonation domains", "medium")
        elif hyphens >= 1 and any(b in self.host for b in KNOWN_BRANDS):
            r.add(8, "Hyphenated domain combined with a recognized brand keyword", "medium")

        labels = self.host.split(".")
        subdomain_count = max(0, len(labels) - 2)
        if subdomain_count >= 3:
            r.add(15, f"Deep subdomain nesting ({subdomain_count} levels) - common cloaking pattern", "medium")

    def _check_shortener(self, r):
        if self.host in URL_SHORTENERS:
            r.add(12, f"URL utilizes a link shortening service ({self.host}) hiding actual destination", "medium")

    def _check_suspicious_tld(self, r):
        for tld in SUSPICIOUS_TLDS:
            if self.host.endswith(tld):
                r.add(8, f"Domain uses a TLD with high threat association ({tld})", "low")
                break

    def _check_keywords(self, r):
        path_and_query = unquote(self.parsed.path + "?" + self.parsed.query).lower()
        hits = [k for k in SUSPICIOUS_KEYWORDS if k in self.host or k in path_and_query]
        if hits:
            unique = sorted(set(hits))
            r.add(min(15, 4 * len(unique)), f"Contains credential harvesting/urgency keywords: {', '.join(unique[:5])}", "medium")

    def _check_typosquatting(self, r):
        labels = self.host.split(".")
        if len(labels) < 2:
            return
        domain_core = labels[-2]
        chunks = [c for c in domain_core.split("-") if c]

        for brand in KNOWN_BRANDS:
            if domain_core == brand:
                continue

            candidates = [domain_core] + chunks
            best = min(candidates, key=lambda c: levenshtein(c, brand))
            dist = levenshtein(best, brand)
            if 0 < dist <= 2 and len(best) >= 4:
                r.add(30, f"Domain label '{best}' closely mimics legitimate brand '{brand}' (Levenshtein distance {dist})", "high")
                break
            if brand in self.host and domain_core != brand:
                r.add(18, f"Brand name '{brand}' embedded in an unauthorized domain structure", "high")
                break

    def _check_entropy(self, r):
        core = self.host.split(".")[0]
        ent = shannon_entropy(core)
        if ent > 3.8 and len(core) > 8:
            r.add(8, f"Subdomain/label '{core}' exhibits high character randomness (entropy {ent:.2f})", "low")

    def _check_port(self, r):
        if self.parsed.port and self.parsed.port not in (80, 443):
            r.add(6, f"Non-standard HTTP port specified ({self.parsed.port})", "low")

    def _check_punycode(self, r):
        if self.host.startswith("xn--") or ".xn--" in self.host:
            r.add(20, "Domain uses Punycode (xn--) encoding - potential Internationalized Domain Name (IDN) homograph attack", "high")

    def analyze_network_and_dns(self, report: RiskReport):
        if not self.host:
            return
        try:
            ip_list = socket.gethostbyname_ex(self.host)[2]
            primary_ip = ip_list[0] if ip_list else ""
            report.details["dns"]["ip"] = primary_ip
            report.details["dns"]["ips"] = ip_list
            try:
                hostname, _, _ = socket.gethostbyaddr(primary_ip)
                report.details["dns"]["hostname"] = hostname
            except Exception:
                report.details["dns"]["hostname"] = "N/A"
        except socket.gaierror:
            report.details["dns"]["error"] = "DNS resolution offline / unresolvable host"

    def analyze_ssl(self, report: RiskReport):
        if not self.host or self.parsed.scheme != "https":
            return

        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        try:
            with socket.create_connection((self.host, self.port), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    report.details["ssl"]["protocol"] = ssock.version()
                    
                    subject_dict = dict(x[0] for x in cert.get("subject", ()))
                    issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
                    
                    subj_cn = subject_dict.get("commonName", "")
                    issuer_org = issuer_dict.get("organizationName") or issuer_dict.get("commonName", "")
                    
                    report.details["ssl"]["subject"] = subj_cn
                    report.details["ssl"]["issuer"] = issuer_org
                    
                    not_after_str = cert.get("notAfter", "")
                    report.details["ssl"]["not_after"] = not_after_str
                    
                    if not_after_str:
                        not_after_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        days_left = (not_after_dt - datetime.utcnow()).days
                        report.details["ssl"]["days_remaining"] = days_left
                        if days_left < 14:
                            report.add(15, f"SSL/TLS Certificate expires in {days_left} days", "medium")

                    alt_names = [item[1] for item in cert.get("subjectAltName", ()) if item[0] == "DNS"]
                    report.details["ssl"]["sans"] = alt_names[:10]

        except ssl.SSLCertVerificationError as e:
            report.add(25, f"SSL Certificate Verification Failed: {e.verify_message}", "high")
            report.details["ssl"]["error"] = str(e)
        except Exception as e:
            report.details["ssl"]["error"] = f"Could not inspect SSL certificate ({e.__class__.__name__})"

    def analyze_http_response(self, report: RiskReport):
        req = urllib.request.Request(
            self.raw,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            }
        )

        try:
            with urllib.request.urlopen(req, timeout=8) as response:
                final_url = response.geturl()
                status_code = response.getcode()
                headers = dict(response.info())

                report.details["http"]["status"] = status_code
                report.details["http"]["final_url"] = final_url
                report.details["http"]["server"] = headers.get("Server", "N/A")
                report.details["http"]["content_type"] = headers.get("Content-Type", "N/A")

                sec_headers = {
                    "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Missing"),
                    "Content-Security-Policy": headers.get("Content-Security-Policy", "Missing"),
                    "X-Frame-Options": headers.get("X-Frame-Options", "Missing"),
                    "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Missing")
                }
                report.details["security_headers"] = sec_headers

                missing_sec = [k for k, v in sec_headers.items() if v == "Missing"]
                if len(missing_sec) >= 3:
                    report.add(5, f"Missing key security headers: {', '.join(missing_sec)}", "low")

                orig_host = (self.parsed.hostname or "").lower()
                final_host = (urlparse(final_url).hostname or "").lower()
                if final_host and orig_host and final_host != orig_host:
                    report.add(12, f"URL redirects to a different host domain ('{orig_host}' -> '{final_host}')", "medium")

                content_type = headers.get("Content-Type", "").lower()
                if "text/html" in content_type:
                    raw_bytes = response.read(500000)
                    html_text = raw_bytes.decode("utf-8", errors="ignore")
                    
                    inspector = SimpleHTMLInspector()
                    inspector.feed(html_text)

                    report.details["content"]["title"] = inspector.title.strip()
                    report.details["content"]["meta_description"] = inspector.meta_description.strip()
                    report.details["content"]["forms_count"] = len(inspector.forms)
                    report.details["content"]["password_inputs"] = inspector.password_inputs
                    report.details["content"]["hidden_iframes"] = inspector.hidden_iframes
                    report.details["content"]["obfuscated_scripts"] = inspector.obfuscated_scripts

                    if inspector.password_inputs > 0:
                        report.add(5, f"Page contains {inspector.password_inputs} password field(s) - verify legitimacy before submitting credentials", "low")

                    for form in inspector.forms:
                        act = form.get("action", "")
                        if act and not act.startswith("#") and not act.startswith("javascript:"):
                            act_host = (urlparse(act).hostname or "").lower()
                            if act_host and act_host != final_host:
                                report.add(25, f"Form submits credentials/data to an external domain ('{act_host}')", "high")
                                break

                    if inspector.hidden_iframes > 0:
                        report.add(15, f"Page embeds {inspector.hidden_iframes} hidden/invisible iframe(s)", "medium")

                    if inspector.obfuscated_scripts > 0:
                        report.add(12, f"Page contains obfuscated JavaScript functions (eval/unescape)", "medium")

                    if inspector.favicon_url:
                        fav_host = (urlparse(inspector.favicon_url).hostname or "").lower()
                        if fav_host and fav_host != final_host:
                            for brand in KNOWN_BRANDS:
                                if brand in fav_host and brand not in final_host:
                                    report.add(15, f"Favicon resource loaded from '{fav_host}' matching brand '{brand}'", "medium")
                                    break

        except urllib.error.HTTPError as e:
            report.details["http"]["status"] = e.code
            report.add(8, f"Server returned HTTP error status code {e.code}", "low")
        except urllib.error.URLError as e:
            report.details["http"]["error"] = f"Network connection failed: {e.reason}"
        except Exception as e:
            report.details["http"]["error"] = f"HTTP inspection error ({e.__class__.__name__})"

def analyze_url_deep(url: str, network_check: bool = True) -> RiskReport:
    report = RiskReport(url=url)
    analyzer = DeepURLAnalyzer(url)
    analyzer.analyze_lexical(report)
    if network_check:
        analyzer.analyze_network_and_dns(report)
        analyzer.analyze_ssl(report)
        analyzer.analyze_http_response(report)
    return report

def main():
    parser = argparse.ArgumentParser(description="Deep Website & Phishing Risk Analyzer")
    parser.add_argument("url", help="URL to analyze (e.g., https://example.com)")
    parser.add_argument("--no-network", action="store_true", help="Disable network/DNS/SSL/HTTP live checks")
    parser.add_argument("--json", action="store_true", help="Output analysis report in JSON format")
    args = parser.parse_args()

    report = analyze_url_deep(args.url, network_check=not args.no_network)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        report.print_report()

    sys.exit(0 if report.score < 40 else 1)

if __name__ == "__main__":
    main()
