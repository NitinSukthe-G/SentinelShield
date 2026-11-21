"""
Prometheus-style metrics export for SentinelShield.

Produces a plain-text exposition that a monitoring stack (Prometheus,
Grafana Agent, etc.) could scrape. Generating the text needs no extra
dependencies; wiring it to an HTTP endpoint is left to the deployment.
"""

import logger


def _sanitise(label):
    return str(label).replace("\\", "").replace('"', "").replace("\n", " ")


def prometheus_text(events=None, reputation_snapshot=None):
    stats = logger.summarize(events)
    lines = []

    def metric(name, value, help_text, mtype="gauge", labels=None):
        key = f"sentinelshield_{name}"
        if not any(line == f"# TYPE {key} {mtype}" for line in lines):
            lines.append(f"# HELP {key} {help_text}")
            lines.append(f"# TYPE {key} {mtype}")
        label_str = ""
        if labels:
            inner = ",".join(f'{k}="{_sanitise(v)}"' for k, v in labels.items())
            label_str = "{" + inner + "}"
        lines.append(f"{key}{label_str} {value}")

    metric("requests_total", stats["total"], "Total requests processed", "counter")
    for action, count in stats["actions"].items():
        metric("requests_by_action", count,
               "Requests by decision", "counter",
               {"action": action})
    for category, count in stats["categories"].items():
        metric("attacks_by_category", count,
               "Detected attacks by category", "counter",
               {"category": category})
    for severity, count in stats["severities"].items():
        if severity:
            metric("events_by_severity", count,
                   "Events by severity", "counter",
                   {"severity": severity})

    if reputation_snapshot is not None:
        banned = sum(1 for r in reputation_snapshot if r.get("banned"))
        tracked = len(reputation_snapshot)
        metric("ips_tracked", tracked, "Distinct source IPs tracked")
        metric("ips_banned", banned, "Currently banned source IPs")

    return "\n".join(lines) + "\n"
