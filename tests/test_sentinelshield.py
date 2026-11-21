"""
SentinelShield test suite.

Run from the project root with:  pytest -q
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import detector  # noqa: E402
import engine as engine_mod  # noqa: E402
from rate_limiter import BehaviorMonitor, IPReputation, RateLimiter  # noqa: E402
from rules import DETECTION_RULES  # noqa: E402


class FakeClock:
    def __init__(self, start=1000.0):
        self.t = start

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


# ----------------------------------------------------------------------
# Normalisation
# ----------------------------------------------------------------------
def test_normalize_url_decoding():
    text, steps = detector.normalize("%3Cscript%3E")
    assert "<script>" in text
    assert any("URL-decode" in s["step"] for s in steps)


def test_normalize_double_encoding():
    text, _ = detector.normalize("%252e%252e%252f")
    assert "../" in text


def test_normalize_html_entities():
    text, _ = detector.normalize("&lt;script&gt;")
    assert "<script>" in text


def test_normalize_sql_comment_strip():
    text, _ = detector.normalize("UNION/**/SELECT")
    assert "union select" in text.lower()


def test_normalize_none():
    text, steps = detector.normalize(None)
    assert text == "" and steps == []


# ----------------------------------------------------------------------
# Detection: previously-missed payloads must now be caught
# ----------------------------------------------------------------------
PREVIOUS_FALSE_NEGATIVES = [
    ("' OR '1'='1", "SQL Injection"),
    ("admin'--", "SQL Injection"),
    ("%3Cscript%3Ealert(1)%3C/script%3E", "Cross-Site Scripting (XSS)"),
    ("1%20UNION%20SELECT%20password", "SQL Injection"),
    ("<iframe src=x>", "Cross-Site Scripting (XSS)"),
    ("<a onmouseover=alert(1)>", "Cross-Site Scripting (XSS)"),
    ("..%2f..%2f", "Directory Traversal"),
    ("/etc/shadow", "Local File Inclusion (LFI)"),
    ("php://filter/convert.base64-encode/resource=index.php", "Local File Inclusion (LFI)"),
    ("; ls -la", "Command Injection"),
    ("| cat /etc/hosts", "Command Injection"),
    ("$(whoami)", "Command Injection"),
    ("`id`", "Command Injection"),
]


@pytest.mark.parametrize("payload,expected", PREVIOUS_FALSE_NEGATIVES)
def test_previous_false_negatives_now_detected(payload, expected):
    result = detector.detect_threat(payload)
    assert result["detected"], f"missed: {payload!r}"
    assert result["category"] == expected


# ----------------------------------------------------------------------
# Detection: benign strings must NOT be flagged
# ----------------------------------------------------------------------
BENIGN = [
    "I want to select a dress from the shop",
    "Please delete from my cart the blue shoes",
    "search=hello",
    "name=O'Brien&city=Pune",
    "What does OR mean in logic? True or false",
    "The script of the movie was amazing",
    "cat and dog photos",
    "union station parking",
    "ping me when you are online",
    "Meet me at 10:30; bring the id card",
]


@pytest.mark.parametrize("text", BENIGN)
def test_benign_not_detected(text):
    assert not detector.detect_threat(text)["detected"], f"false positive: {text!r}"


# ----------------------------------------------------------------------
# Every rule has at least one benchmark sample it is responsible for
# and all rules compile.
# ----------------------------------------------------------------------
def test_all_rules_compile_and_have_fields():
    for rule in DETECTION_RULES:
        assert rule["regex"] is not None
        for field in ("id", "name", "category", "severity", "score", "owasp", "cwe"):
            assert field in rule


def test_new_categories_detected():
    cases = {
        "${jndi:ldap://x.invalid/a}": "Log4Shell (JNDI Injection)",
        "url=http://169.254.169.254/latest/meta-data/": "Server-Side Request Forgery (SSRF)",
        "name={{7*7}}": "Server-Side Template Injection (SSTI)",
        "password[$ne]=x": "NoSQL Injection",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>': "XML External Entity (XXE)",
    }
    for payload, expected in cases.items():
        assert detector.detect_threat(payload)["category"] == expected


# ----------------------------------------------------------------------
# Full-request inspection and locations
# ----------------------------------------------------------------------
def test_inspect_request_reports_location():
    req = detector.build_request(
        method="GET", path="/search", query="q=<script>alert(1)</script>", ip="1.2.3.4"
    )
    verdict = detector.inspect_request(req)
    assert verdict["detected"]
    assert any(m["location"] == "query" for m in verdict["matches"])


def test_scanner_user_agent_detected_in_header():
    req = detector.build_request(headers={"User-Agent": "sqlmap/1.7"}, ip="1.2.3.4")
    verdict = detector.inspect_request(req)
    assert verdict["detected"]
    assert verdict["category"] == "Automated Scanner"


# ----------------------------------------------------------------------
# Parsers
# ----------------------------------------------------------------------
def test_parse_raw_http():
    raw = (
        "POST /login HTTP/1.1\n"
        "Host: example.com\n"
        "User-Agent: nikto\n"
        "Cookie: session=abc; theme=dark\n"
        "\n"
        "user=admin&pass=' OR 1=1--"
    )
    req = detector.parse_raw_http(raw)
    assert req["method"] == "POST"
    assert req["path"] == "/login"
    assert req["cookies"]["session"] == "abc"
    verdict = detector.inspect_request(req)
    assert verdict["detected"]


def test_parse_curl():
    cmd = "curl -X POST 'http://site/login' -H 'User-Agent: x' -d \"q=<script>alert(1)</script>\""
    req = detector.parse_curl(cmd)
    assert req["method"] == "POST"
    assert req["path"] == "/login"
    assert "<script>" in req["body"]


# ----------------------------------------------------------------------
# Rate limiting / behaviour
# ----------------------------------------------------------------------
def test_rate_limiter_window():
    clock = FakeClock()
    rl = RateLimiter(max_requests=3, window_seconds=60, clock=clock)
    assert rl.check_request("ip")["allowed"]
    assert rl.check_request("ip")["allowed"]
    assert rl.check_request("ip")["allowed"]
    assert not rl.check_request("ip")["allowed"]
    clock.advance(61)
    assert rl.check_request("ip")["allowed"]


def test_brute_force_detection():
    clock = FakeClock()
    bm = BehaviorMonitor(brute_force_max=5, brute_force_window=60, clock=clock)
    result = {}
    for _ in range(5):
        result = bm.record("ip", path="/login")
    assert result["brute_force"]


def test_scanner_detection():
    clock = FakeClock()
    bm = BehaviorMonitor(scan_path_threshold=5, scan_window=60, clock=clock)
    result = {}
    for i in range(5):
        result = bm.record("ip", path=f"/page{i}")
    assert result["scanning"]


# ----------------------------------------------------------------------
# IP reputation and bans
# ----------------------------------------------------------------------
def test_ban_escalation():
    clock = FakeClock()
    rep = IPReputation(clock=clock, persist=False)
    # 3 strikes -> first ban
    for _ in range(3):
        rep.record("evil", score=6, blocked=True)
    assert rep.is_banned("evil")
    remaining = rep.ban_remaining("evil")
    assert remaining > 0


def test_allowlist_overrides_ban():
    rep = IPReputation(persist=False)
    rep.add_deny("1.2.3.4")
    assert rep.is_banned("1.2.3.4")
    rep.add_allow("1.2.3.4")
    assert not rep.is_banned("1.2.3.4")


def test_manual_ban_and_unban():
    rep = IPReputation(persist=False)
    rep.ban("9.9.9.9")
    assert rep.is_banned("9.9.9.9")
    rep.unban("9.9.9.9")
    assert not rep.is_banned("9.9.9.9")


def test_reputation_persistence(tmp_path):
    state = tmp_path / "ip_state.json"
    rep = IPReputation(state_file=str(state), persist=True)
    rep.ban("5.5.5.5")
    rep2 = IPReputation(state_file=str(state), persist=True)
    assert rep2.is_banned("5.5.5.5")


# ----------------------------------------------------------------------
# Engine pipeline
# ----------------------------------------------------------------------
def test_engine_blocks_attack():
    eng = engine_mod.WAFEngine(persist=False)
    req = detector.build_request(query="id=1' OR '1'='1", ip="7.7.7.7")
    event = eng.process(req, store=False)
    assert event["action"] == engine_mod.BLOCKED


def test_engine_allows_benign():
    eng = engine_mod.WAFEngine(persist=False)
    req = detector.build_request(query="q=hello world", ip="7.7.7.8")
    event = eng.process(req, store=False)
    assert event["action"] == engine_mod.ALLOWED


def test_engine_monitor_mode_never_blocks():
    eng = engine_mod.WAFEngine(mode=engine_mod.MODE_MONITOR, persist=False)
    req = detector.build_request(query="id=1' OR '1'='1", ip="7.7.7.9")
    event = eng.process(req, store=False)
    assert "monitored" in event["action"]


def test_engine_rate_limits_flood():
    clock = FakeClock()
    eng = engine_mod.WAFEngine(rate_max=3, rate_window=60, persist=False, clock=clock)
    actions = [eng.process(detector.build_request(query="q=hi", ip="8.8.8.8"), store=False)["action"] for _ in range(5)]
    assert engine_mod.RATE_LIMITED in actions


def test_engine_bans_repeat_offender():
    eng = engine_mod.WAFEngine(persist=False)
    actions = []
    for _ in range(4):
        actions.append(
            eng.process(detector.build_request(query="id=1' OR '1'='1", ip="6.6.6.6"), store=False)["action"]
        )
    assert engine_mod.BANNED in actions


# ----------------------------------------------------------------------
# Access-log forensics
# ----------------------------------------------------------------------
def test_access_log_analysis():
    log = (
        '203.0.113.5 - - [10/Nov/2026:10:00:00 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 100 "-" "Mozilla"\n'
        '198.51.100.9 - - [10/Nov/2026:10:00:01 +0000] "GET /?id=1 UNION SELECT 1,2 HTTP/1.1" 500 0 "-" "sqlmap/1.7"\n'
        '203.0.113.5 - - [10/Nov/2026:10:00:02 +0000] "GET / HTTP/1.1" 200 100 "-" "Mozilla"\n'
    )
    result = detector.analyze_access_log(log)
    assert result["total_lines"] == 3
    assert result["malicious_lines"] >= 2
    assert result["unique_ips"] == 2


# ----------------------------------------------------------------------
# Benchmark accuracy guarantees
# ----------------------------------------------------------------------
def test_benchmark_zero_false_positives_and_high_recall():
    result = detector.evaluate_corpus()
    assert result["fp"] == 0, f"false positives: {result['false_positives']}"
    assert result["recall"] >= 0.95, f"recall too low: {result['recall']:.3f}, misses: {result['false_negatives']}"
    assert result["accuracy"] >= 0.95


# ----------------------------------------------------------------------
# Logger round-trip + legacy compatibility
# ----------------------------------------------------------------------
def test_logger_roundtrip(tmp_path, monkeypatch):
    import logger

    monkeypatch.setattr(logger, "LOG_FILE", str(tmp_path / "events.json"))
    monkeypatch.setattr(logger, "ALERT_FILE", str(tmp_path / "alerts.json"))
    logger.clear_events()
    logger.log_event("1.1.1.1", "SQL Injection", "BLOCKED", "payload", "High")
    events = logger.load_events()
    assert len(events) == 1
    assert events[0]["category"] == "SQL Injection"


def test_report_generation(tmp_path, monkeypatch):
    import logger

    monkeypatch.setattr(logger, "LOG_FILE", str(tmp_path / "events.json"))
    monkeypatch.setattr(logger, "ALERT_FILE", str(tmp_path / "alerts.json"))
    logger.clear_events()
    logger.record_event(
        {
            "ip_address": "2.2.2.2",
            "category": "SQL Injection",
            "action": "BLOCKED",
            "severity": "High",
            "score": 6,
            "rule_ids": ["SS-SQLI-002"],
        },
        raise_alert=True,
    )
    bench = detector.evaluate_corpus()
    report = logger.generate_report(benchmark=bench)
    assert "SentinelShield Security Report" in report
    assert "Detection Accuracy" in report
    assert len(logger.load_alerts()) == 1


def test_legacy_detect_threat_api():
    result = detector.detect_threat("")
    assert result["detected"] is False
    assert result["category"] == "Normal"
