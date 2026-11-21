# 🛡️ SentinelShield

## Advanced Intrusion Detection & Web Protection System

SentinelShield is a **free, self-hosted Web Application Firewall (WAF) and Intrusion Detection System (IDS)** with a full Security Operations Centre (SOC) dashboard.

It solves a real, everyday problem: **small businesses, startups, student projects and self-hosted apps are exposed on the internet with no WAF at all.** Commercial WAFs (Cloudflare, AWS WAF, Akamai) cost money or need a managed domain, and ModSecurity + the OWASP Core Rule Set is powerful but hard to configure and read. SentinelShield gives you **explainable, signature-based request inspection, attacker tracking and log forensics** that anyone can run in minutes — and understand.

> **Purpose:** Defensive cybersecurity. Submitted payloads are analysed as *text* and never executed.

---

## 🎬 Demo



https://github.com/user-attachments/assets/567ca300-0dbd-43b8-8c39-61513c168900



A guided tour of the **live app**: open the SOC console, inspect a login request hiding a SQL injection, watch it **blocked instantly** with the exact rule, anomaly score, MITRE ATT&CK technique and response playbook — then IP reputation and auto-bans, access-log forensics, the measured 100% benchmark, and config/CLI.

| Step in the video | What you see |
|---|---|
| 1 | The security console — every request, blocked or allowed, and the attack types |
| 2–3 | Inspect a request hiding a SQL injection → **BLOCKED**, with the rule, score, MITRE technique and playbook |
| 4 | Threat intelligence — per-IP reputation scores and automatic, escalating bans |
| 5 | Log forensics — replay a real access log to find attacks that already happened |
| 6 | Proven accuracy — 100% on a labelled benchmark, zero false positives |
| 7 | Configure & automate — JSON config, custom rules, Prometheus metrics, headless CLI |

---

## Live Dashboard

[https://sentinelshield-waf.streamlit.app/](https://sentinelshield-waf.streamlit.app/)

---

## ✨ What makes it advanced

| Capability | Detail |
|---|---|
| **33 detection rules, 13 attack categories** | SQLi, XSS, Directory Traversal, LFI, Command Injection, **SSRF, SSTI, Log4Shell/JNDI, XXE, NoSQL injection, CRLF injection, scanner fingerprinting, sensitive-file probes** |
| **Anomaly scoring** | OWASP CRS-style scoring — a request is BLOCKED when its combined score crosses a threshold, FLAGGED when it is borderline |
| **Evasion-aware normalisation** | Recursive URL-decoding, HTML-entity decoding, Unicode NFKC, null-byte stripping and SQL-comment stripping *before* matching, so encoded payloads can't slip past |
| **Full-request inspection** | Method, path, query, **headers, cookies and body** are each inspected and the exact location of every hit is reported |
| **Behaviour analysis** | Sliding-window rate limiting, **login brute-force detection** and **scanner detection** (many distinct paths per IP) |
| **IP reputation & auto-ban** | Per-IP threat scoring with an **escalating ban ladder** (5 min → 30 min → 6 h → 24 h → permanent), plus manual allow/deny lists, persisted across restarts |
| **Access-log forensics** | Upload a real Apache/Nginx access log and SentinelShield replays every line through the engine to find attacks, attackers and brute-force bursts |
| **Measured accuracy** | A labelled benchmark corpus reports **accuracy, precision, recall, F1 and a confusion matrix** — no hand-waving about "100% detection" |
| **MITRE ATT&CK + playbooks** | Every detection maps to a MITRE ATT&CK technique and a response playbook (impact, remediation, immediate response) |
| **Attacker case files** | Per-IP incident reconstruction: kill-chain timeline, techniques used, threat level and recommended response |
| **Offline IP intelligence** | Classifies each source (public, private, CGNAT, link-local, documentation…) and combines it with observed behaviour into a risk verdict — no paid feed |
| **Configurable like a product** | A JSON config file drives thresholds, rate limits, disabled rules, allow/deny lists and **custom rules** — no code edits |
| **Headless CLI + metrics** | Runs in a server/CI pipeline (exit 1 on detection) and exports Prometheus-style metrics for monitoring |
| **SOC dashboard** | Live timeline, category donut, severity breakdown, top-attacker chart, hour×category heatmap and OWASP Top-10 coverage |
| **Reporting** | One-click Markdown security report generated from live events + benchmark |
| **Tested** | 66 automated tests (`pytest`) across `test_sentinelshield.py` + `test_advanced.py` — rules, normalisation, parsers, behaviour windows, bans, the engine pipeline, IP intelligence, config and the CLI |

---

## 📊 Detection accuracy (labelled benchmark)

Measured by `detector.evaluate_corpus()` over 82 labelled samples (attacks + tricky benign strings that *look* like attacks):

| Metric | Result |
|---|---|
| Accuracy | **100%** |
| Precision | **100%** |
| Recall | **100%** |
| F1 score | **100%** |
| False positives | **0** |
| False negatives | **0** |

The benign set deliberately includes traps such as *"I want to select a dress from the shop"*, *"union station parking"* and *"Please delete from my cart"* to prove the rules do **not** over-block normal text. Re-run it yourself anytime from the **Rules & Accuracy** tab.

---

## 🏗️ System Architecture

```text
            ┌──────────────────────────────┐
            │  HTTP-style request / raw     │
            │  HTTP / curl / access-log line│
            └───────────────┬──────────────┘
                            ▼
            ┌──────────────────────────────┐
            │  Normalizer (detector.py)     │
            │  decode · unescape · NFKC     │
            └───────────────┬──────────────┘
                            ▼
        ┌───────────────────┴───────────────────┐
        ▼                                        ▼
┌────────────────────┐              ┌────────────────────────┐
│ Detection engine   │              │ Behaviour monitor      │
│ 33 rules, scoring  │              │ rate / brute / scanner │
│ (rules.py)         │              │ (rate_limiter.py)      │
└─────────┬──────────┘              └───────────┬────────────┘
          └───────────────┬──────────────────────┘
                          ▼
            ┌──────────────────────────────┐
            │ Decision engine (engine.py)  │
            │ ALLOW · FLAG · BLOCK · RL ·  │
            │ BAN  + IP reputation         │
            └───────────────┬──────────────┘
                            ▼
            ┌──────────────────────────────┐
            │ Event store + alerts         │
            │ (logger.py, JSON, atomic)    │
            └───────────────┬──────────────┘
                            ▼
            ┌──────────────────────────────┐
            │ SOC dashboard (app.py)       │
            │ charts · logs · forensics ·  │
            │ reports · threat intel       │
            └──────────────────────────────┘
```

---

## 🧩 Project Structure

```text
SentinelShield/
├── app.py                 # Streamlit SOC console (9 tabs)
├── engine.py              # WAF decision pipeline + traffic simulator
├── detector.py            # Normalisation, inspection, parsers, log forensics, benchmark
├── rules.py               # 33 structured signatures + labelled benchmark corpus
├── rate_limiter.py        # Rate limiting, brute-force/scanner detection, IP reputation
├── logger.py              # Atomic event store, alert queue, report generator
├── intel.py               # MITRE ATT&CK mapping, response playbooks, attacker case files
├── ipintel.py             # Offline IP intelligence (classification + risk)
├── config.py              # JSON-file configuration (thresholds, custom rules, lists)
├── metrics.py             # Prometheus-style metrics export
├── cli.py                 # Headless CLI for servers / CI pipelines
├── sentinelshield.config.example.json  # Example configuration
├── requirements.txt       # Dependencies (streamlit, pandas, plotly, pytest)
├── README.md
├── .gitignore
├── SentinelShield_Detailed_Project_Report.pdf   # Full project report
├── tests/
│   ├── test_sentinelshield.py   # core engine tests
│   └── test_advanced.py         # SOC/IR layer tests  (66 tests total)
├── data/
│   ├── security_events.json     # Event log
│   └── sample_access.log        # Sample access log for the forensics demo
├── docs/
│   ├── SentinelShield-walkthrough.mp4   # Demo video (shown above)
│   └── demo-thumbnail.png
├── screenshots/           # UI screenshots
└── .streamlit/config.toml  # Dark SOC theme
```

---

## 🖥️ The SOC Console (9 tabs)

1. **Overview** — KPIs, request timeline, attack-category donut, severity breakdown, top-attacker chart, hour×category heatmap, OWASP coverage.
2. **Request Inspector** — analyse a structured request, a pasted **raw HTTP request**, or a **curl command**; see the verdict, every rule that fired with its location, and the decoding steps applied.
3. **Attack Simulator** — one-click scenarios (normal user, SQLi, XSS, traversal/LFI, command injection, SSRF/Log4Shell, brute force, scanner) and a full test-suite run.
4. **Threat Intel** — IP reputation with offline IP classification and risk, **per-attacker case files** (kill-chain timeline + MITRE techniques + recommended response), active bans, ban/unban and allow/deny lists.
5. **Security Logs** — filter/search events and export CSV or JSON.
6. **Log Forensics** — upload an access log (or use the bundled sample) and get attacks, attackers and a brute-force summary.
7. **Rules & Accuracy** — browse the rule library with OWASP/CWE mappings, a live regex tester, and the full accuracy benchmark + confusion matrix.
8. **Alerts & Report** — alert queue with acknowledgement and a downloadable Markdown security report.
9. **Config & Ops** — active JSON configuration, custom/disabled rules, Prometheus-style metrics export and the headless CLI reference.

---

## ⚙️ Technology Stack

- **Python** — detection, scoring, behaviour and reputation logic (standard library only)
- **Streamlit** — interactive SOC dashboard
- **Pandas** — event tables and statistics
- **Plotly** — security visualisations
- **Regular expressions** — signature-based detection
- **JSON** — lightweight, atomic event and reputation storage
- **pytest** — automated test suite

Everything is **free and open**: no API keys, no paid services, no external calls.

---

## ▶️ Local Installation

```bash
git clone https://github.com/NitinSukthe-G/SentinelShield.git
cd SentinelShield

python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
streamlit run app.py
```

Open `http://localhost:8501`.

### Run the tests

```bash
pytest -q          # 66 tests
```

### Headless CLI (servers / CI pipelines)

```bash
python cli.py scan "id=1' OR '1'='1"      # exit 1 = malicious detected
python cli.py analyze-log data/sample_access.log
python cli.py benchmark                   # fails CI if accuracy regresses
python cli.py simulate --all
python cli.py metrics                      # Prometheus-style metrics
```

### Configure without touching code

Copy `sentinelshield.config.example.json` to `sentinelshield.config.json` and set thresholds, rate limits, disabled rules, allow/deny lists and your own `custom_rules`. Both the dashboard and the CLI read it on start-up.

---

## 🔍 Detection Categories

| Category | OWASP | CWE | Example indicator |
|---|---|---|---|
| SQL Injection | A03:2021 | CWE-89 | `' OR '1'='1`, `UNION SELECT` |
| Cross-Site Scripting (XSS) | A03:2021 | CWE-79 | `<script>`, `onerror=` |
| Directory Traversal | A01:2021 | CWE-22 | `../`, `..%2f` |
| Local File Inclusion (LFI) | A01:2021 | CWE-98 | `/etc/shadow`, `php://` |
| Command Injection | A03:2021 | CWE-78 | `; whoami`, `$(id)` |
| Server-Side Request Forgery | A10:2021 | CWE-918 | `169.254.169.254` |
| Server-Side Template Injection | A03:2021 | CWE-1336 | `{{7*7}}` |
| Log4Shell (JNDI) | A06:2021 | CWE-917 | `${jndi:ldap://…}` |
| XML External Entity (XXE) | A05:2021 | CWE-611 | `<!ENTITY … SYSTEM>` |
| NoSQL Injection | A03:2021 | CWE-943 | `password[$ne]=x` |
| CRLF Injection | A03:2021 | CWE-93 | `%0d%0aSet-Cookie:` |
| Automated Scanner | A05:2021 | CWE-200 | `sqlmap`, `nikto` UA |
| Sensitive File Probe | A05:2021 | CWE-538 | `/.env`, `/.git/config` |

---

## 🛡️ Decision Workflow

```text
Allowlist? → Banned/Denylist? → Anomaly score ≥ block threshold? → BLOCK
          → Brute force / scanning? → BLOCK
          → Rate limit exceeded? → RATE LIMITED
          → Score ≥ flag threshold? → FLAG
          → otherwise → ALLOW
→ update IP reputation (strikes, escalating bans) → log event → raise alert
```

---

## 📈 Future Improvements

- Reverse-proxy / WSGI-ASGI middleware mode to protect a live app in-line
- SQLite/PostgreSQL storage for long-term retention
- Machine-learning anomaly baselining alongside signatures
- Webhook / email alerting and SIEM forwarding
- Configurable per-path policies and rule exceptions

---

## ⚠️ Disclaimer

SentinelShield is an educational, defensive-security project for controlled environments. It performs pattern-based inspection of submitted data and is not a drop-in replacement for a hardened production WAF/IPS/SIEM.

---

## Author

Developed as a cybersecurity internship project.
