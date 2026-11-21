"""
SentinelShield event store, alert queue and report generator.

Events and alerts are stored as JSON with atomic, thread-safe writes so
the dashboard never reads a half-written file. The original
``log_event`` signature is preserved for backward compatibility while a
richer ``record_event`` captures full detection detail.
"""

import json
import os
import threading
import uuid
from collections import Counter
from datetime import datetime

LOG_FILE = "data/security_events.json"
ALERT_FILE = "data/alerts.json"

_lock = threading.Lock()


# ----------------------------------------------------------------------
# Low-level atomic JSON helpers
# ----------------------------------------------------------------------
def _read_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return default


def _write_json(path, data):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, path)


# ----------------------------------------------------------------------
# Events
# ----------------------------------------------------------------------
def load_events():
    return _read_json(LOG_FILE, [])


def clear_events():
    with _lock:
        _write_json(LOG_FILE, [])


def record_event(event, raise_alert=False):
    """Append a fully-formed event dict and optionally raise an alert."""
    event.setdefault("event_id", uuid.uuid4().hex[:12])
    event.setdefault("timestamp", datetime.now().isoformat(timespec="seconds"))
    with _lock:
        events = _read_json(LOG_FILE, [])
        events.append(event)
        _write_json(LOG_FILE, events)
        if raise_alert:
            _append_alert(event)
    return event


def log_event(ip_address, category, action, request_data="", severity="Medium"):
    """
    Backward-compatible logging entry point (original API). Builds a
    minimal event and stores it.
    """
    event = {
        "event_id": uuid.uuid4().hex[:12],
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "ip_address": ip_address,
        "category": category,
        "action": action,
        "severity": severity,
        "request": request_data,
        "method": "",
        "path": "",
        "score": 0,
        "rule_ids": [],
        "locations": [],
    }
    return record_event(event)


# ----------------------------------------------------------------------
# Alerts
# ----------------------------------------------------------------------
def load_alerts():
    return _read_json(ALERT_FILE, [])


def _append_alert(event):
    alerts = _read_json(ALERT_FILE, [])
    alerts.append(
        {
            "alert_id": uuid.uuid4().hex[:12],
            "event_id": event.get("event_id"),
            "timestamp": event.get("timestamp"),
            "ip_address": event.get("ip_address"),
            "category": event.get("category"),
            "severity": event.get("severity"),
            "action": event.get("action"),
            "score": event.get("score", 0),
            "request": event.get("request", ""),
            "acknowledged": False,
        }
    )
    _write_json(ALERT_FILE, alerts)


def acknowledge_alert(alert_id):
    with _lock:
        alerts = _read_json(ALERT_FILE, [])
        for alert in alerts:
            if alert.get("alert_id") == alert_id:
                alert["acknowledged"] = True
        _write_json(ALERT_FILE, alerts)


def acknowledge_all_alerts():
    with _lock:
        alerts = _read_json(ALERT_FILE, [])
        for alert in alerts:
            alert["acknowledged"] = True
        _write_json(ALERT_FILE, alerts)


def clear_alerts():
    with _lock:
        _write_json(ALERT_FILE, [])


# ----------------------------------------------------------------------
# Exports and reporting
# ----------------------------------------------------------------------
def export_json(events=None):
    events = events if events is not None else load_events()
    return json.dumps(events, indent=2, default=str)


def export_csv(events=None):
    import csv
    import io

    events = events if events is not None else load_events()
    columns = [
        "timestamp",
        "event_id",
        "ip_address",
        "method",
        "path",
        "category",
        "action",
        "severity",
        "score",
        "request",
    ]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for event in events:
        writer.writerow(event)
    return buf.getvalue()


def summarize(events=None):
    """Return aggregate counters used by the dashboard and reports."""
    events = events if events is not None else load_events()
    actions = Counter(e.get("action", "") for e in events)
    categories = Counter(
        e.get("category", "") for e in events if e.get("category") not in ("", "Normal")
    )
    severities = Counter(e.get("severity", "") for e in events)
    attackers = Counter(
        e.get("ip_address", "")
        for e in events
        if e.get("action") in ("BLOCKED", "RATE LIMITED", "BANNED", "FLAGGED")
    )
    rules = Counter()
    for e in events:
        for rid in e.get("rule_ids", []):
            rules[rid] += 1
    return {
        "total": len(events),
        "actions": dict(actions),
        "categories": dict(categories),
        "severities": dict(severities),
        "top_attackers": attackers.most_common(10),
        "top_rules": rules.most_common(10),
    }


def generate_report(events=None, benchmark=None):
    """
    Produce a Markdown incident / practical report from the stored
    events and (optionally) the accuracy benchmark results.
    """
    events = events if events is not None else load_events()
    stats = summarize(events)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "# SentinelShield Security Report",
        "",
        f"Generated: {now}",
        "",
        "## 1. Executive Summary",
        "",
        f"- Total requests processed: **{stats['total']}**",
        f"- Blocked: **{stats['actions'].get('BLOCKED', 0)}**",
        f"- Flagged: **{stats['actions'].get('FLAGGED', 0)}**",
        f"- Rate limited: **{stats['actions'].get('RATE LIMITED', 0)}**",
        f"- Banned: **{stats['actions'].get('BANNED', 0)}**",
        f"- Allowed: **{stats['actions'].get('ALLOWED', 0)}**",
        "",
        "## 2. Attacks by Category",
        "",
    ]
    if stats["categories"]:
        lines.append("| Category | Count |")
        lines.append("|---|---|")
        for cat, count in sorted(stats["categories"].items(), key=lambda x: -x[1]):
            lines.append(f"| {cat} | {count} |")
    else:
        lines.append("_No malicious activity recorded._")

    lines += ["", "## 3. Top Attacker IPs", ""]
    if stats["top_attackers"]:
        lines.append("| Source IP | Malicious events |")
        lines.append("|---|---|")
        for ip, count in stats["top_attackers"]:
            if ip:
                lines.append(f"| {ip} | {count} |")
    else:
        lines.append("_No repeat offenders identified._")

    lines += ["", "## 4. Most Triggered Rules", ""]
    if stats["top_rules"]:
        lines.append("| Rule ID | Hits |")
        lines.append("|---|---|")
        for rid, count in stats["top_rules"]:
            lines.append(f"| {rid} | {count} |")
    else:
        lines.append("_No rule hits recorded._")

    if benchmark:
        lines += [
            "",
            "## 5. Detection Accuracy (labelled benchmark)",
            "",
            f"- Samples: **{benchmark['total']}**",
            f"- Accuracy: **{benchmark['accuracy'] * 100:.1f}%**",
            f"- Precision: **{benchmark['precision'] * 100:.1f}%**",
            f"- Recall: **{benchmark['recall'] * 100:.1f}%**",
            f"- F1 score: **{benchmark['f1'] * 100:.1f}%**",
            f"- False positives: **{benchmark['fp']}**",
            f"- False negatives: **{benchmark['fn']}**",
            f"- Correct category (of detected attacks): **{benchmark['category_accuracy'] * 100:.1f}%**",
        ]
        if benchmark["false_positives"]:
            lines += ["", "**False positives:**"]
            for fp in benchmark["false_positives"]:
                lines.append(f"- `{fp['input']}` -> {fp['predicted']}")
        if benchmark["false_negatives"]:
            lines += ["", "**False negatives:**"]
            for fn in benchmark["false_negatives"]:
                lines.append(f"- `{fn['input']}` (expected {fn['expected']})")

    lines += [
        "",
        "## 6. Recommendations",
        "",
        "- Keep detection rules under version control and review them regularly.",
        "- Investigate and, where justified, permanently block repeat-offender IPs.",
        "- Enforce rate limiting on authentication endpoints to blunt brute-force attacks.",
        "- Normalise and decode input before validation to defeat encoding-based evasion.",
        "- Forward these events to a central SIEM for long-term correlation.",
        "",
    ]
    return "\n".join(lines)
