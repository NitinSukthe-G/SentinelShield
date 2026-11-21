"""
SentinelShield configuration loader.

Lets an operator tune the WAF from a JSON file (``sentinelshield.config.json``)
the way a real product is configured, rather than editing code:

    {
      "mode": "block",
      "block_threshold": 5,
      "flag_threshold": 3,
      "rate_limit": {"max_requests": 10, "window_seconds": 60},
      "disabled_rules": ["SS-XSS-005"],
      "allowlist": ["203.0.113.10"],
      "denylist": ["45.77.12.9"],
      "custom_rules": [
        {"id": "SS-CUSTOM-001", "name": "Blocked keyword",
         "category": "Command Injection", "severity": "High",
         "score": 6, "pattern": "forbidden_token"}
      ]
    }

All keys are optional; anything omitted keeps the built-in default.
"""

import json
import os
import re

import rules as rules_mod

CONFIG_FILE = "sentinelshield.config.json"

DEFAULTS = {
    "mode": "block",
    "block_threshold": 5,
    "flag_threshold": 3,
    "rate_limit": {"max_requests": 10, "window_seconds": 60},
    "disabled_rules": [],
    "custom_rules": [],
    "allowlist": [],
    "denylist": [],
}


def load_config(path=CONFIG_FILE):
    """Load config from JSON, merged over defaults. Missing file = defaults."""
    cfg = json.loads(json.dumps(DEFAULTS))  # deep copy
    source = "defaults"
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                user = json.load(fh)
            for key, value in user.items():
                cfg[key] = value
            source = path
        except (json.JSONDecodeError, OSError) as exc:
            cfg["_error"] = f"Could not read {path}: {exc}"
    cfg["_source"] = source
    return cfg


def apply_rule_config(cfg):
    """
    Apply disabled_rules and custom_rules to the shared rule set.
    Idempotent: removes previously-added custom rules before re-adding.
    Returns (enabled_count, custom_count, errors).
    """
    errors = []
    disabled = set(cfg.get("disabled_rules", []))

    # Remove any custom rules added on a previous call.
    rules_mod.DETECTION_RULES[:] = [
        r for r in rules_mod.DETECTION_RULES if not r.get("_custom")
    ]

    # Toggle enabled state on built-in rules.
    for rule in rules_mod.DETECTION_RULES:
        rule["enabled"] = rule["id"] not in disabled

    # Compile and append custom rules.
    custom_count = 0
    for spec in cfg.get("custom_rules", []):
        try:
            rule = {
                "id": spec["id"],
                "name": spec.get("name", spec["id"]),
                "category": spec.get("category", "Command Injection"),
                "severity": spec.get("severity", "High"),
                "score": int(spec.get("score", 5)),
                "pattern": spec["pattern"],
                "stage": spec.get("stage", "both"),
                "targets": spec.get("targets", ["any"]),
                "enabled": True,
                "_custom": True,
                "description": spec.get("description", "User-defined rule."),
            }
            owasp, cwe = rules_mod.OWASP_MAP.get(rule["category"], ("-", "-"))
            rule["owasp"] = spec.get("owasp", owasp)
            rule["cwe"] = spec.get("cwe", cwe)
            rule["regex"] = re.compile(rule["pattern"], re.IGNORECASE)
            rules_mod.DETECTION_RULES.append(rule)
            custom_count += 1
        except (KeyError, re.error) as exc:
            errors.append(f"custom rule {spec.get('id', '?')}: {exc}")

    # Refresh derived lookups.
    rules_mod.RULES_BY_ID.clear()
    rules_mod.RULES_BY_ID.update({r["id"]: r for r in rules_mod.DETECTION_RULES})
    rules_mod.CATEGORIES[:] = list(
        dict.fromkeys(r["category"] for r in rules_mod.DETECTION_RULES)
    )

    enabled_count = sum(1 for r in rules_mod.DETECTION_RULES if r.get("enabled", True))
    return enabled_count, custom_count, errors


def apply_to_engine(engine, cfg):
    """Apply thresholds, mode, rate limit and allow/deny lists to an engine."""
    engine.block_threshold = int(cfg.get("block_threshold", 5))
    engine.flag_threshold = int(cfg.get("flag_threshold", 3))
    engine.mode = "monitor" if str(cfg.get("mode", "block")).startswith("monitor") else "block"

    rl = cfg.get("rate_limit", {})
    engine.behavior.rate_limiter.max_requests = int(rl.get("max_requests", 10))
    engine.behavior.rate_limiter.window_seconds = int(rl.get("window_seconds", 60))

    for ip in cfg.get("allowlist", []):
        engine.reputation.add_allow(ip)
    for ip in cfg.get("denylist", []):
        engine.reputation.add_deny(ip)
    return engine
