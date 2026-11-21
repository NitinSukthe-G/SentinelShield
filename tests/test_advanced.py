"""
Tests for the advanced SOC/IR layer: threat intel, IP intelligence,
config-driven rules, metrics and the CLI.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cli  # noqa: E402
import config as config_mod  # noqa: E402
import detector  # noqa: E402
import intel  # noqa: E402
import ipintel  # noqa: E402
import metrics as metrics_mod  # noqa: E402
import rules as rules_mod  # noqa: E402


# ----------------------------------------------------------------------
# Threat intel
# ----------------------------------------------------------------------
def test_mitre_mapping_present_for_all_categories():
    for rule in rules_mod.DETECTION_RULES:
        tid, name = intel.mitre_for(rule["category"])
        assert tid.startswith("T") and name


def test_playbook_has_required_fields():
    pb = intel.playbook_for("SQL Injection")
    assert pb["impact"] and pb["remediation"] and pb["response"]


def test_attacker_case_file():
    events = [
        {"ip_address": "9.9.9.9", "timestamp": "2026-11-10T10:00:00", "method": "GET",
         "path": "/a", "category": "SQL Injection", "action": "BLOCKED", "severity": "High", "score": 6},
        {"ip_address": "9.9.9.9", "timestamp": "2026-11-10T10:01:00", "method": "GET",
         "path": "/b", "category": "Cross-Site Scripting (XSS)", "action": "BLOCKED", "severity": "High", "score": 6},
        {"ip_address": "1.1.1.1", "timestamp": "2026-11-10T10:02:00", "method": "GET",
         "path": "/c", "category": "Normal", "action": "ALLOWED", "severity": "Low", "score": 0},
    ]
    case = intel.attacker_case_file(events, "9.9.9.9")
    assert case["malicious_requests"] == 2
    assert case["distinct_categories"] == 2
    assert len(case["techniques"]) == 2
    assert case["threat_level"] in ("Medium", "High", "Critical")
    assert case["recommended_response"]


def test_case_file_unknown_ip():
    assert intel.attacker_case_file([], "0.0.0.0") is None


# ----------------------------------------------------------------------
# IP intelligence
# ----------------------------------------------------------------------
def test_classify_addresses():
    assert ipintel.classify_address("127.0.0.1")["type"] == "loopback"
    assert ipintel.classify_address("10.0.0.5")["type"] == "private"
    assert ipintel.classify_address("169.254.169.254")["type"] == "link-local"
    assert ipintel.classify_address("100.64.0.1")["type"] == "cgnat"
    assert ipintel.classify_address("203.0.113.10")["type"] == "documentation"
    assert ipintel.classify_address("8.8.8.8")["type"] == "public"
    assert ipintel.classify_address("not-an-ip")["type"] == "unknown"


def test_enrich_risk_levels():
    assert ipintel.enrich("8.8.8.8", {"strikes": 0, "score": 0})["risk"] == "Benign"
    assert ipintel.enrich("8.8.8.8", {"strikes": 1, "score": 3})["risk"] == "Suspicious"
    assert ipintel.enrich("8.8.8.8", {"strikes": 3, "score": 18})["risk"] == "Malicious"
    assert ipintel.enrich("8.8.8.8", {"banned": True, "bans": 1})["risk"] == "Blocked"


# ----------------------------------------------------------------------
# Config-driven rules
# ----------------------------------------------------------------------
def test_config_defaults_when_missing(tmp_path):
    cfg = config_mod.load_config(str(tmp_path / "nope.json"))
    assert cfg["block_threshold"] == 5
    assert cfg["_source"] == "defaults"


def test_custom_rule_applied_and_removable(tmp_path):
    cfg_path = tmp_path / "ss.json"
    cfg_path.write_text(json.dumps({
        "custom_rules": [{
            "id": "SS-CUSTOM-TEST", "name": "Codename",
            "category": "Sensitive File Probe", "severity": "High",
            "score": 6, "pattern": "projectfalcon"}]
    }))
    cfg = config_mod.load_config(str(cfg_path))
    enabled, custom, errors = config_mod.apply_rule_config(cfg)
    assert custom == 1 and not errors
    assert detector.detect_threat("give me projectfalcon docs")["detected"]
    # Reapplying empty config removes the custom rule again.
    config_mod.apply_rule_config(config_mod.DEFAULTS)
    assert not detector.detect_threat("give me projectfalcon docs")["detected"]


def test_disable_rule(tmp_path):
    cfg = {"disabled_rules": ["SS-XSS-001"], "custom_rules": []}
    config_mod.apply_rule_config(cfg)
    rule = rules_mod.RULES_BY_ID["SS-XSS-001"]
    assert rule["enabled"] is False
    # Restore for other tests.
    config_mod.apply_rule_config(config_mod.DEFAULTS)
    assert rules_mod.RULES_BY_ID["SS-XSS-001"]["enabled"] is True


# ----------------------------------------------------------------------
# Metrics
# ----------------------------------------------------------------------
def test_prometheus_metrics_format():
    events = [
        {"action": "BLOCKED", "category": "SQL Injection", "severity": "High"},
        {"action": "ALLOWED", "category": "Normal", "severity": "Low"},
    ]
    text = metrics_mod.prometheus_text(events=events, reputation_snapshot=[{"banned": True}])
    assert "sentinelshield_requests_total 2" in text
    assert "# TYPE sentinelshield_requests_total counter" in text
    assert "sentinelshield_ips_banned 1" in text


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
def test_cli_scan_exit_codes():
    assert cli.main(["scan", "hello world"]) == 0
    assert cli.main(["scan", "' OR 1=1 --"]) == 1


def test_cli_benchmark_passes():
    assert cli.main(["benchmark"]) == 0


def test_cli_analyze_log():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "data", "sample_access.log")
    assert cli.main(["analyze-log", path]) == 1  # sample contains attacks


def test_cli_inspect_curl():
    rc = cli.main(["inspect", "--curl", "curl 'http://x/?q=<script>alert(1)</script>'"])
    assert rc == 1


def test_cli_simulate_and_metrics():
    assert cli.main(["simulate", "--all"]) == 0
    assert cli.main(["metrics"]) == 0
