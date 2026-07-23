import re
import sys
import math
import argparse
import ipaddress
from dataclasses import dataclass , field
from urllib.parse import  urlparse, unquote
KNOWN_BRANDS = [
    "paypal", "apple", "google", "microsoft", "facebook", "amazon", "linkedin",
    "twitter", "instagram", "dropbox", "yahoo", "ebay", "wellsfargo", "chase", "bankofamerica", "citibank", "hsbc", "barclays",
    "netflix", "spotify", "adobe", "salesforce", "slack", "zoom", "twitch", "reddit", "tumblr", "pinterest","adobe", "salesforce",
    "slack", "zoom", "twitch", "reddit", "tumblr", "pinterest","adobe", "salesforce", "slack", "zoom", "twitch", "reddit", "tumblr",
    "pinterest"
 ]
SUSPICIOUS_TLDS = {
    ".zip", ".review", ".country", ".kim", ".cricket", ".work", ".party", ".gq", ".ml", ".tk", ".cf", ".ga", ".xyz", ".top",
    ".club", ".online", ".site", ".website", ".space", ".tech",".link", ".click", ".download", ".host", ".info", ".press", ".pro", ".store", 
    ".vip", ".win", ".world", ".zone", ".bid", ".loan",
}
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd", "buff.ly", "adf.ly", "shorte.st", "cutt.ly",
    "shorturl.at", "tiny.cc", "mcaf.ee", "soo.gd", "v.gd", "cli.gs", "tr.im", "u.to", "x.co"
}
SUSPICIOUS_KEYWORDS = [
    "login", "secure", "account", "update", "verify", "confirm", "password", "banking", "billing",
    "paypal", "appleid", "signin", "reset", "verification", "credentials", "access", "identity",
    "suspicious", "fraud", "scam", "phishing"
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

@dataclass
class Finding:
    points: int
    reason: str
    severity: str

@dataclass
class RiskReport:
    url: str
    findings: list = field(default_factory=list)

    @property
    def score(self) -> int:
        return min(100, sum(f.points for f in self.findings))

    @property
    def verdict(self) -> str:
        s = self.score
        if s >= 70:
            return "HIGH RISK _ likely phishing"
        if s >= 40:
            return "SUSPICIOUS _ potential phishing"
        if s >= 15:
            return "LOW RISK _ minor red flags"
        return "LIKELY SAFE _ no significant indicators"

    def add(self, points, reason, severity="low"):
        self.findings.append(Finding(points, reason, severity))

    def print_report(self):
        bar_len = 30
        filled = int(bar_len * self.score / 100)
        bar = " " * filled + "-" * (bar_len - filled)

        print("=" * 60)
        print(f"PHISING RISK REPORT")
        print("=" * 60)
        print(f"URL:  {self.url}")
        print(f"Score:  [{bar}] {self.score}/100")
        print(f"Verdict:  {self.verdict}")
        print("_" * 60)
        if not self.findings:
            print("No indicators detected.")
        else:
            ordered = sorted(self.findings, key=lambda f: f.points)
            for f in ordered:
                tag = {"high": "[!!!]", "medium": "[!! ]", "low": "[! ]"}[f.severity]
                print(f"{tag} +{f.points:>3} {f.reason}")
        print("=" * 60)

class URLAnalyzer:
    def __init__(self, url: str):
        if not re.match(r"^\w+://", url):
            url = "http://" + url
        self.raw = url
        self.parsed = urlparse(url)
        self.host = (self.parsed.hostname or "").lower()

    def analyze(self, report: RiskReport):
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
            ipaddress.ip_address(self.host)
            r.add(25, f"hostname is a raw IP address ({self.host}) instead of a domain name", "high")
        except ValueError:
            pass

    def _check_https(self, r):
        if self.parsed.scheme != "https":
            r.add(10, "Connection is not HTTPS (no TLS encryption)", "medium")

    def _check_at_symbol(self, r):
        if "@" in self.raw:
            r.add(20, "URL contains '@' - text before '@' is decorative; browser navigates to whatever follows it", "high")

    def _check_length(self, r):
        n = len(self.raw)
        if n > 100:
            r.add(10, f"Unusually long URL ({n} characters) - often used to hide the real destination", "medium")
        elif n > 75:
            r.add(5, f"Long URL ({n} characters) - may be used to obfuscate the real destination", "low")

    def _check_hyphens_and_subdomains(self, r):
        hyphens = self.host.count("-")
        if hyphens >= 3:
            r.add(10, f"Domains contains {hyphens} (common in fake lookalike domains, e.g. 'secure-login-paypal-verify.com')", "medium")
        elif hyphens >= 1 and any(b in self.host for b in KNOWN_BRANDS):
            r.add(8, "Hyphenated domain combined with a brand-name "
                  "keyword", "medium")

        labels = self.host.split(".")
        subdomain_count = max(0, len(labels) - 2)
        if subdomain_count >= 3:
            r.add(15, f"Excessive subdomain nesting ({subdomain_count} "
                  "levels) - a common cloaking technique", "medium")
    def _check_shortener(self, r):
        if self.host in URL_SHORTENERS:
            r.add(12, f"URL uses a link-shortening service ({self.host}) "
                f"which hides the true destination", "medium")

    def _check_suspicious_tld(self, r):
        for tld in SUSPICIOUS_TLDS:
            if self.host.endswith(tld):
                r.add(8, f"Domain uses a TLD frequently abused for "
                f"phishing (.{tld})", "low")
                break

    def _check_keywords(self, r):
        path_and_query = unquote(self.parsed.path + "?" + self.parsed.query).lower()
        hits = [k for k in SUSPICIOUS_KEYWORDS if k in self.host or k in path_and_query]
        if hits:
            unique = sorted(set(hits))
            r.add(min(15, 4 * len(unique)), f"Contains urgency/credential-harvesting keywords: {', '.join(unique[:5])}", "medium")

    def _check_typosquatting(self, r):
        # Strip TLD to compare bare domain names
        labels = self.host.split(".")
        if len(labels) < 2:
            return
        domain_core = labels[-2]  # e.g. "paypa1" from "paypa1.com"
        # Also check each hyphen-separated chunk, e.g. "paypa1" in "paypa1-secure-login"
        chunks = [c for c in domain_core.split("-") if c]

        for brand in KNOWN_BRANDS:
            if domain_core == brand:
                continue  # exact match, not a typosquat by itself

            candidates = [domain_core] + chunks
            best = min(candidates, key=lambda c: levenshtein(c, brand))
            dist = levenshtein(best, brand)
            if 0 < dist <= 2 and len(best) >= 4:
                r.add(30, f"Domain contains '{best}', closely resembling known brand '{brand}' (edit distance {dist}) — likely typosquatting", "high")
                break
            # substring brand-stuffing, e.g. "paypal-security-check"
            if brand in self.host and domain_core != brand:
                r.add(18, f"Brand name '{brand}' embedded in a domain that isn't the brand's actual domain", "high")
                break

    def _check_entropy(self, r):
        core = self.host.split(".")[0]
        ent = shannon_entropy(core)
        if ent > 3.8 and len(core) > 8:
            r.add(8, f"Subdomain/label '{core}' has high randomness (entropy {ent:.2f}) — resembles auto-generated phishing infrastructure", "low")

    def _check_port(self, r):
        if self.parsed.port and self.parsed.port not in (80, 443):
            r.add(6, f"Non-standard port specified ({self.parsed.port})", "low")

    def _check_punycode(self, r):
        if self.host.startswith("xn--") or ".xn--" in self.host:
            r.add(20, "Domain uses Punycode (xn--) encoding — can be used to spoof lookalike characters (IDN homograph attack)", "high")


# ---------------------------------------------------------------------------
# Layer 2: Live content analysis (optional, requires network + requests/bs4)
# ---------------------------------------------------------------------------

class ContentAnalyzer:
    """Fetches and inspects the actual page. Kept separate so URL-only
    analysis (Layer 1) never needs network access or extra dependencies."""

    def __init__(self, url: str, timeout: int = 8):
        self.url = url
        self.timeout = timeout

    def analyze(self, report: RiskReport):
        try:
            import importlib
            requests = importlib.import_module("requests")
            bs4 = importlib.import_module("bs4")
            BeautifulSoup = getattr(bs4, "BeautifulSoup")
        except ImportError:
            report.add(0, "Content analysis skipped: 'requests'/'beautifulsoup4' not installed", "low")
            return

        try:
            resp = requests.get(
                self.url, timeout=self.timeout,
                headers={"User-Agent": "Mozilla/5.0 (compatible; PhishDetector/1.0)"},
                allow_redirects=True,
            )
        except requests.exceptions.SSLError:
            report.add(20, "TLS certificate error while connecting — invalid/self-signed cert", "high")
            return
        except requests.RequestException as e:
            report.add(5, f"Could not fetch page content ({e.__class__.__name__})", "low")
            return

        final_host = urlparse(resp.url).hostname or ""
        orig_host = urlparse(self.url).hostname or ""
        if final_host and orig_host and final_host != orig_host:
            report.add(10, f"URL redirected from '{orig_host}' to a different host '{final_host}'", "medium")

        soup = BeautifulSoup(resp.text, "html.parser")

        self._check_password_forms(soup, resp.url, report)
        self._check_external_form_action(soup, final_host, report)
        self._check_hidden_iframes(soup, report)
        self._check_favicon_mismatch(soup, final_host, report)
        self._check_obfuscated_scripts(soup, report)
        self._check_login_without_https(resp, report)

    def _check_password_forms(self, soup, url, report):
        pw_inputs = soup.find_all("input", {"type": "password"})
        if pw_inputs:
            report.add(5, f"Page contains {len(pw_inputs)} password input field(s) — verify domain matches the real service before entering credentials", "low")

    def _check_external_form_action(self, soup, page_host, report):
        for form in soup.find_all("form"):
            action = form.get("action", "")
            if not action or action.startswith("#") or action.startswith("javascript:"):
                continue
            action_host = urlparse(action).hostname
            if action_host and action_host != page_host:
                report.add(25, f"A form on the page submits data to a different domain ('{action_host}') than the page itself ('{page_host}')", "high")

    def _check_hidden_iframes(self, soup, report):
        for iframe in soup.find_all("iframe"):
            style = (iframe.get("style") or "").replace(" ", "")
            w = iframe.get("width", "")
            h = iframe.get("height", "")
            if "display:none" in style or w in ("0", "1") or h in ("0", "1"):
                report.add(15, "Hidden/invisible iframe detected — sometimes used to load malicious content covertly", "medium")
                break

    def _check_favicon_mismatch(self, soup, page_host, report):
        icon = soup.find("link", rel=lambda x: x and "icon" in x.lower())
        if icon and icon.get("href"):
            icon_host = urlparse(icon["href"]).hostname
            if icon_host and icon_host != page_host:
                for brand in KNOWN_BRANDS:
                    if brand in icon_host and brand not in page_host:
                        report.add(15, f"Favicon is loaded from '{icon_host}', impersonating brand '{brand}', while the page domain is '{page_host}'", "medium")
                        break

    def _check_obfuscated_scripts(self, soup, report):
        for script in soup.find_all("script"):
            text = script.string or ""
            if re.search(r"eval\s*\(|unescape\s*\(|fromCharCode", text):
                report.add(10, "Page contains obfuscated JavaScript (eval/unescape/fromCharCode) — common in credential-stealing scripts", "medium")
                break

    def _check_login_without_https(self, resp, report):
        if resp.url.startswith("http://") and (b"password" in resp.content.lower() or b"login" in resp.content.lower()):
            report.add(15, "Login-related content served over unencrypted HTTP", "medium")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def analyze_url(url: str, fetch: bool = False) -> RiskReport:
    report = RiskReport(url=url)
    URLAnalyzer(url).analyze(report)
    if fetch:
        ContentAnalyzer(url).analyze(report)
    return report


def main():
    parser = argparse.ArgumentParser(description="Phishing Website Detector")
    parser.add_argument("url", help="URL to analyze, e.g. https://example.com")
    parser.add_argument("--fetch", action="store_true",
                         help="Download and inspect live page content (requires requests + beautifulsoup4)")
    args = parser.parse_args()

    report = analyze_url(args.url, fetch=args.fetch)
    report.print_report()

    sys.exit(0 if report.score < 40 else 1)


if __name__ == "__main__":
    main()