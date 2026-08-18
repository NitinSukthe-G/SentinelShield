import json
import os
from datetime import datetime


LOG_FILE = "data/security_events.json"


def log_event(
    ip_address,
    category,
    action,
    request_data="",
    severity="Medium"
):
    event = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "ip_address": ip_address,
        "category": category,
        "action": action,
        "severity": severity,
        "request": request_data
    }

    os.makedirs("data", exist_ok=True)

    events = []

    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as file:
                events = json.load(file)
        except (json.JSONDecodeError, FileNotFoundError):
            events = []

    events.append(event)

    with open(LOG_FILE, "w", encoding="utf-8") as file:
        json.dump(events, file, indent=4)

    return event