# SentinelX — Explainable Phishing Threat Intelligence

SentinelX is a defensive cybersecurity project that detects suspicious and phishing-style URLs using explainable heuristics. It combines a presentation-ready browser dashboard with a deeper Python command-line analyzer for DNS, TLS, HTTP headers, redirects, forms, iframes, and obfuscated scripts.

> The project is designed for security education, hackathons, SOC workflow prototypes, and phishing-awareness demonstrations. It does not claim that a URL is safe; it highlights risk signals that should inform human review.

## Why this project matters

Phishing links often exploit several small signals at once: a misspelled brand, a misleading subdomain, urgency words, an unusual TLD, Punycode, or an insecure connection. SentinelX converts those signals into a transparent risk score and explains exactly why each point was added.

This explainability is useful to:

- help users understand *why* a link looks dangerous;
- give analysts a fast first-pass triage report;
- demonstrate feature engineering before introducing machine learning;
- provide judges and mentors with a clear, testable security workflow.

## Highlights

- Modern black-and-red threat-intelligence dashboard
- 12+ deterministic URL heuristics
- Brand typosquatting detection using Levenshtein distance
- Punycode/IDN, raw-IP, `@` redirect, URL shortener, entropy, port, and TLD checks
- Credential-harvesting and urgency keyword detection
- Explainable 0–100 score with severity-ranked evidence
- Session investigation history
- One-click JSON report copy and export
- Safe browser demo: parses input locally and does not visit the submitted URL
- Python deep scan for DNS, TLS certificates, response headers, redirects, forms, hidden iframes, and suspicious scripts
- JSON and human-readable CLI output

## Project structure

```text
.
├── index.html            # Standalone interactive dashboard
├── phising_detector.py   # Python deep-analysis CLI
└── README.md             # Project documentation
```

## Detection pipeline

```text
Submitted URL
    │
    ├── Normalize and parse
    ├── Inspect lexical structure
    │   ├── raw IP / @ symbol / unusual port
    │   ├── URL length / subdomain depth / entropy
    │   └── suspicious TLD / shortener / keywords
    ├── Compare domain with known brands
    │   └── edit-distance and embedded-brand checks
    ├── Detect Punycode/IDN patterns
    ├── Optional Python network inspection
    │   ├── DNS and TLS certificate
    │   ├── HTTP response and redirects
    │   ├── security headers
    │   └── forms, password fields, iframes, scripts
    └── Produce score, verdict, evidence, and JSON report
```

## Risk levels

| Score | Verdict | Suggested response |
|---:|---|---|
| 0–14 | Likely safe | Continue with normal caution |
| 15–39 | Low risk | Review minor red flags |
| 40–69 | Suspicious | Do not open; verify independently |
| 70–100 | High risk | Isolate, report, and investigate |

The score is capped at 100. It is an explainable heuristic score, not a probability produced by a trained model.

## Run the dashboard

No build step or dependency installation is required.

```bash
python3 -m http.server 8080
```

Then open `http://localhost:8080`.

You can also open `index.html` directly, although serving it locally gives more consistent browser behavior for clipboard and download features.

## Run the Python analyzer

Python 3.9+ is recommended. The CLI uses only the standard library.

```bash
python3 phising_detector.py "https://example.com"
```

Return structured JSON:

```bash
python3 phising_detector.py "http://paypa1-secure-login.tk/verify-account" --json
```

Run only lexical checks, without DNS/HTTP/TLS requests:

```bash
python3 phising_detector.py "http://192.168.1.1/admin/login" --no-network
```

The command exits with status `0` when the score is below 40 and `1` for suspicious/high-risk results, so it can be incorporated into scripts or CI experiments.

## Demonstration scenarios

The dashboard includes safe text-only samples:

1. `https://www.wikipedia.org` — a low-risk baseline.
2. `http://paypa1-secure-login.tk/verify-account/update.php` — typosquatting, insecure transport, suspicious TLD, and credential keywords.
3. `http://192.168.1.1/admin/login.php` — raw IP, HTTP, and login wording.
4. `https://accounts.google.xn--80ak6aa92e/signin` — a Punycode/IDN example.

The dashboard does not navigate to these targets.

## Browser demo vs. Python engine

| Capability | Browser dashboard | Python CLI |
|---|:---:|:---:|
| Lexical URL analysis | Yes | Yes |
| Explainable score | Yes | Yes |
| Brand similarity | Yes | Yes |
| JSON report | Yes | Yes |
| DNS resolution | No (display-only inference) | Yes |
| TLS certificate inspection | No | Yes |
| HTTP/security headers | No | Yes |
| HTML form/script inspection | No | Yes |

This distinction is intentionally visible: the dashboard remains safe and instant, while the CLI performs active network inspection only when the operator requests it.

## Responsible use and limitations

- Use the network scanner only on targets you are authorized to inspect.
- Never submit credentials to a site based solely on this tool's verdict.
- A clean score does not prove that a URL or page is harmless.
- Domain age, registrar reputation, threat feeds, screenshot similarity, and email context are not currently included.
- The browser UI performs static URL analysis and labels inferred/network-only fields accordingly.
- Heuristic weights are hand-designed and should be validated on a representative labeled dataset before production use.

## Future implementation roadmap

### Near term

- Connect the dashboard to a small authenticated API that invokes the Python engine
- Add domain age and WHOIS/RDAP signals
- Integrate reputation feeds such as Google Safe Browsing, VirusTotal, or PhishTank
- Generate a downloadable PDF incident report
- Add unit tests and a labeled benchmark dataset with precision/recall metrics

### Intelligence and ML

- Train a baseline classifier on lexical and host-based features
- Compare ML confidence with the deterministic score
- Add visual similarity detection for cloned login pages
- Detect brand logos and page impersonation from screenshots
- Explain model output with feature importance rather than presenting a black box

### Production hardening

- Run live URL inspection in an isolated sandbox with strict timeouts and egress controls
- Block private, loopback, link-local, and cloud-metadata addresses to prevent SSRF
- Add rate limiting, audit logs, caching, and abuse monitoring
- Queue scans asynchronously and stream progress to the UI
- Package the analyzer as a browser extension and an email-security integration

## Suggested judging walkthrough

1. Start with the Wikipedia sample and explain the low baseline score.
2. Scan the typosquat sample and open **Risk Indicators** to show each contributing feature.
3. Show the network and structural tabs to explain the larger analysis model.
4. Export the JSON evidence report.
5. Run the Python CLI with `--no-network`, then explain how an authorized full scan extends the same pipeline.
6. Finish with the roadmap: dataset validation, isolated scanning, threat-intelligence feeds, and explainable ML.

## License and attribution

This repository currently has no explicit software license. Add a license before redistributing or accepting external contributions.
