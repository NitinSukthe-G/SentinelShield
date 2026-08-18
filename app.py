import streamlit as st
import pandas as pd
import json
import os

from detector import detect_threat
from rate_limiter import RateLimiter
from logger import log_event


# --------------------------------------------------
# Page Configuration
# --------------------------------------------------

st.set_page_config(
    page_title="SentinelShield",
    page_icon="🛡️",
    layout="wide"
)


# --------------------------------------------------
# Application Configuration
# --------------------------------------------------

RATE_LIMIT = 10
RATE_WINDOW = 60

if "rate_limiter" not in st.session_state:
    st.session_state.rate_limiter = RateLimiter(
        max_requests=RATE_LIMIT,
        window_seconds=RATE_WINDOW
    )


LOG_FILE = "data/security_events.json"


# --------------------------------------------------
# Helper Functions
# --------------------------------------------------

def load_events():
    if not os.path.exists(LOG_FILE):
        return []

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, FileNotFoundError):
        return []


def process_request(ip_address, request_data):
    """
    Inspect the request, apply detection rules,
    apply rate limiting and generate a security event.
    """

    # Threat detection
    detection = detect_threat(request_data)

    # Rate-limit check
    rate_result = st.session_state.rate_limiter.check_request(ip_address)

    # Determine final decision
    if detection["detected"]:
        action = "BLOCKED"
        category = detection["category"]

        if category in [
            "SQL Injection",
            "Command Injection",
            "Local File Inclusion (LFI)"
        ]:
            severity = "High"
        else:
            severity = "Medium"

    elif not rate_result["allowed"]:
        action = "RATE LIMITED"
        category = "Abusive Traffic"
        severity = "Medium"

    else:
        action = "ALLOWED"
        category = "Normal"
        severity = "Low"

    # Log every request
    event = log_event(
        ip_address=ip_address,
        category=category,
        action=action,
        request_data=request_data,
        severity=severity
    )

    return event


# --------------------------------------------------
# Header
# --------------------------------------------------

st.title("🛡️ SentinelShield")

st.subheader(
    "Advanced Intrusion Detection & Web Protection System"
)

st.markdown(
    """
SentinelShield is a defensive Web Application Firewall (WAF) and
Intrusion Detection System simulator that analyzes HTTP-style request
data, detects suspicious patterns, monitors abusive traffic and
generates security events.
"""
)

st.divider()


# --------------------------------------------------
# Request Inspection
# --------------------------------------------------

st.header("🔍 Request Inspection")

col1, col2 = st.columns(2)

with col1:
    ip_address = st.text_input(
        "Source IP Address",
        value="192.168.1.10"
    )

with col2:
    request_method = st.selectbox(
        "HTTP Method",
        ["GET", "POST", "PUT", "DELETE"]
    )

request_data = st.text_area(
    "Request Parameters / Body",
    placeholder="Enter request data to analyze...",
    height=150
)

if st.button("🔎 Inspect Request", type="primary"):

    if not request_data.strip():
        st.warning("Please enter request data.")
    else:

        event = process_request(
            ip_address,
            request_data
        )

        st.divider()

        if event["action"] == "ALLOWED":
            st.success("✅ REQUEST ALLOWED")

        elif event["action"] == "RATE LIMITED":
            st.warning("⚠️ REQUEST RATE LIMITED")

        else:
            st.error("🚨 REQUEST BLOCKED")

        result_col1, result_col2, result_col3, result_col4 = st.columns(4)

        with result_col1:
            st.metric(
                "Decision",
                event["action"]
            )

        with result_col2:
            st.metric(
                "Category",
                event["category"]
            )

        with result_col3:
            st.metric(
                "Severity",
                event["severity"]
            )

        with result_col4:
            st.metric(
                "Source IP",
                event["ip_address"]
            )


st.divider()


# --------------------------------------------------
# Security Dashboard
# --------------------------------------------------

st.header("📊 Security Dashboard")

events = load_events()

if events:

    df = pd.DataFrame(events)

    total_events = len(df)

    blocked_events = len(
        df[df["action"] == "BLOCKED"]
    )

    allowed_events = len(
        df[df["action"] == "ALLOWED"]
    )

    rate_limited_events = len(
        df[df["action"] == "RATE LIMITED"]
    )

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Total Requests",
            total_events
        )

    with col2:
        st.metric(
            "Blocked",
            blocked_events
        )

    with col3:
        st.metric(
            "Allowed",
            allowed_events
        )

    with col4:
        st.metric(
            "Rate Limited",
            rate_limited_events
        )

    st.subheader("Attack Distribution")

    attack_events = df[
        df["category"] != "Normal"
    ]

    if not attack_events.empty:

        category_counts = (
            attack_events["category"]
            .value_counts()
        )

        st.bar_chart(category_counts)

    else:
        st.info("No malicious activity detected yet.")

    st.subheader("Security Event Logs")

    display_columns = [
        "timestamp",
        "ip_address",
        "category",
        "action",
        "severity",
        "request"
    ]

    st.dataframe(
        df[display_columns],
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "No security events recorded yet. "
        "Submit a request above to generate events."
    )


st.divider()


# --------------------------------------------------
# Security Information
# --------------------------------------------------

st.header("🛡️ Detection Capabilities")

capabilities = pd.DataFrame({
    "Detection Type": [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "Directory Traversal",
        "Local File Inclusion (LFI)",
        "Command Injection",
        "Abusive Traffic"
    ],
    "Protection": [
        "Pattern-based detection",
        "Script pattern detection",
        "Traversal sequence detection",
        "Sensitive file pattern detection",
        "Command pattern detection",
        "IP-based rate limiting"
    ]
})

st.table(capabilities)