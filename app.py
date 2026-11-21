"""
SentinelShield - Advanced Intrusion Detection & Web Protection System.

A self-hosted, free, explainable Web Application Firewall and IDS with a
Security Operations Centre (SOC) dashboard. Inspects HTTP-style requests
against 33 signature rules across 13 attack categories, tracks attacker
behaviour and IP reputation, performs access-log forensics and measures
its own detection accuracy.
"""

import os
from datetime import datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

import config as config_mod
import detector
import intel
import ipintel
import logger
import metrics as metrics_mod
from engine import (
    ALLOWED,
    BLOCKED,
    FLAGGED,
    MODE_BLOCK,
    MODE_MONITOR,
    RATE_LIMITED,
    SCENARIOS,
    WAFEngine,
    run_all_scenarios,
    run_scenario,
)
import rules as rules_mod
from rules import CATEGORIES, DETECTION_RULES

# ----------------------------------------------------------------------
# Page configuration & theme helpers
# ----------------------------------------------------------------------
st.set_page_config(
    page_title="SentinelShield SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

ACTION_COLORS = {
    "ALLOWED": "#2dd4bf",
    "FLAGGED": "#fbbf24",
    "BLOCKED": "#f87171",
    "RATE LIMITED": "#fb923c",
    "BANNED": "#a78bfa",
}
SEVERITY_COLORS = {
    "Low": "#2dd4bf",
    "Medium": "#fbbf24",
    "High": "#fb923c",
    "Critical": "#f87171",
}

st.markdown(
    """
    <style>
      .block-container {padding-top: 2rem;}
      div[data-testid="stMetric"] {
        background: rgba(148,163,184,0.08);
        border: 1px solid rgba(148,163,184,0.18);
        border-radius: 12px; padding: 14px 16px;
      }
      .ss-badge {display:inline-block;padding:3px 10px;border-radius:999px;
        font-size:0.78rem;font-weight:600;margin-right:6px;}
      .ss-hero h1 {margin-bottom:0;}
    </style>
    """,
    unsafe_allow_html=True,
)


# ----------------------------------------------------------------------
# Shared engine (single instance across sessions)
# ----------------------------------------------------------------------
@st.cache_resource
def get_engine():
    cfg = config_mod.load_config()
    config_mod.apply_rule_config(cfg)
    eng = WAFEngine(persist=True)
    config_mod.apply_to_engine(eng, cfg)
    return eng, cfg


engine, loaded_cfg = get_engine()


def plotly(fig):
    fig.update_layout(
        margin=dict(l=10, r=10, t=40, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#e2e8f0"),
        legend=dict(bgcolor="rgba(0,0,0,0)"),
    )
    st.plotly_chart(fig, width="stretch")


def events_df():
    events = logger.load_events()
    if not events:
        return pd.DataFrame()
    df = pd.DataFrame(events)
    for col in ["timestamp", "ip_address", "category", "action", "severity",
                "score", "method", "path", "request"]:
        if col not in df.columns:
            df[col] = ""
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["score"] = pd.to_numeric(df["score"], errors="coerce").fillna(0).astype(int)
    return df


# ----------------------------------------------------------------------
# Sidebar: policy controls
# ----------------------------------------------------------------------
with st.sidebar:
    st.markdown("## 🛡️ SentinelShield")
    st.caption("Advanced Intrusion Detection & Web Protection System")
    st.divider()

    st.markdown("### ⚙️ WAF Policy")
    mode_label = st.radio(
        "Mode",
        ["Blocking", "Monitor only"],
        help="Blocking enforces decisions. Monitor logs what *would* be blocked without stopping traffic.",
    )
    engine.mode = MODE_BLOCK if mode_label == "Blocking" else MODE_MONITOR

    engine.block_threshold = st.slider("Block threshold (anomaly score)", 3, 15, engine.block_threshold)
    engine.flag_threshold = st.slider("Flag threshold (anomaly score)", 1, engine.block_threshold, min(engine.flag_threshold, engine.block_threshold))
    rate_max = st.slider("Rate limit (requests / 60s)", 3, 50, engine.behavior.rate_limiter.max_requests)
    engine.behavior.rate_limiter.max_requests = rate_max

    st.divider()
    st.markdown("### 📈 Live stats")
    _df = events_df()
    st.metric("Events stored", 0 if _df.empty else len(_df))
    banned_now = sum(1 for r in engine.reputation.snapshot() if r["banned"])
    st.metric("IPs banned", banned_now)

    st.divider()
    if st.button("🧪 Load demo traffic", width="stretch"):
        run_all_scenarios(engine)
        st.success("Demo traffic generated.")
        st.rerun()
    if st.button("🗑️ Reset all data", width="stretch"):
        logger.clear_events()
        logger.clear_alerts()
        engine.reputation.reset()
        get_engine.clear()
        st.success("All events, alerts and reputation cleared.")
        st.rerun()

    st.caption("Defensive security education. Payloads are analysed as text, never executed.")


# ----------------------------------------------------------------------
# Header
# ----------------------------------------------------------------------
st.markdown('<div class="ss-hero">', unsafe_allow_html=True)
st.title("🛡️ SentinelShield")
st.markdown(
    "**A free, self-hosted Web Application Firewall + IDS with a SOC console.** "
    "Protects apps that can't afford a commercial WAF — inspecting every request, "
    "scoring threats, tracking attackers and explaining each decision."
)
st.markdown("</div>", unsafe_allow_html=True)

bench = detector.evaluate_corpus()
h1, h2, h3, h4 = st.columns(4)
h1.metric("Detection rules", len(DETECTION_RULES))
h2.metric("Attack categories", len(CATEGORIES))
h3.metric("Benchmark accuracy", f"{bench['accuracy'] * 100:.0f}%")
h4.metric("False positives", bench["fp"])

st.divider()

tabs = st.tabs([
    "📊 Overview",
    "🔍 Request Inspector",
    "🎯 Attack Simulator",
    "🧠 Threat Intel",
    "📋 Security Logs",
    "🕵️ Log Forensics",
    "📐 Rules & Accuracy",
    "⚠️ Alerts & Report",
    "⚙️ Config & Ops",
])

# ======================================================================
# TAB 1 - OVERVIEW
# ======================================================================
with tabs[0]:
    df = events_df()
    if df.empty:
        st.info("No events yet. Use **Load demo traffic** in the sidebar, or try the Request Inspector / Attack Simulator.")
    else:
        stats = logger.summarize(logger.load_events())
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Total requests", stats["total"])
        c2.metric("Blocked", stats["actions"].get("BLOCKED", 0))
        c3.metric("Flagged", stats["actions"].get("FLAGGED", 0))
        c4.metric("Rate limited", stats["actions"].get("RATE LIMITED", 0))
        c5.metric("Allowed", stats["actions"].get("ALLOWED", 0))

        left, right = st.columns([3, 2])
        with left:
            st.subheader("Request timeline")
            tl = df.dropna(subset=["timestamp"]).copy()
            if not tl.empty:
                tl["minute"] = tl["timestamp"].dt.floor("min")
                grp = tl.groupby(["minute", "action"]).size().reset_index(name="count")
                fig = px.area(grp, x="minute", y="count", color="action",
                              color_discrete_map=ACTION_COLORS)
                plotly(fig)
            else:
                st.caption("Timeline needs timestamped events.")
        with right:
            st.subheader("Attack categories")
            if stats["categories"]:
                cats = pd.DataFrame(stats["categories"].items(), columns=["category", "count"])
                fig = px.pie(cats, names="category", values="count", hole=0.55)
                fig.update_traces(textposition="inside", textinfo="percent")
                plotly(fig)
            else:
                st.caption("No malicious activity recorded yet.")

        left2, right2 = st.columns(2)
        with left2:
            st.subheader("Top attacker IPs")
            if stats["top_attackers"]:
                atk = pd.DataFrame(stats["top_attackers"], columns=["ip", "events"])
                atk = atk[atk["ip"] != ""]
                fig = px.bar(atk, x="events", y="ip", orientation="h",
                             color="events", color_continuous_scale="Reds")
                fig.update_layout(yaxis=dict(autorange="reversed"), coloraxis_showscale=False)
                plotly(fig)
            else:
                st.caption("No repeat offenders.")
        with right2:
            st.subheader("Severity breakdown")
            sev = df[df["severity"].isin(SEVERITY_COLORS)]
            if not sev.empty:
                sv = sev["severity"].value_counts().reindex(
                    ["Critical", "High", "Medium", "Low"]).dropna().reset_index()
                sv.columns = ["severity", "count"]
                fig = px.bar(sv, x="severity", y="count", color="severity",
                             color_discrete_map=SEVERITY_COLORS)
                fig.update_layout(showlegend=False)
                plotly(fig)
            else:
                st.caption("No severity data.")

        st.subheader("Attack activity by hour and category")
        hm = df[(df["category"] != "Normal") & df["timestamp"].notna()].copy()
        if not hm.empty:
            hm["hour"] = hm["timestamp"].dt.hour
            pivot = hm.pivot_table(index="category", columns="hour",
                                   values="action", aggfunc="count", fill_value=0)
            fig = go.Figure(data=go.Heatmap(
                z=pivot.values, x=[f"{h:02d}:00" for h in pivot.columns],
                y=list(pivot.index), colorscale="Inferno"))
            plotly(fig)
        else:
            st.caption("Heatmap appears once attacks are recorded.")

        st.subheader("OWASP Top 10 coverage")
        owasp = pd.DataFrame(
            [{"Rule": r["id"], "Category": r["category"], "OWASP": r["owasp"],
              "CWE": r["cwe"], "Severity": r["severity"]} for r in DETECTION_RULES]
        )
        cov = owasp.groupby("OWASP").size().reset_index(name="rules")
        fig = px.bar(cov.sort_values("rules"), x="rules", y="OWASP", orientation="h",
                     color="rules", color_continuous_scale="Teal")
        fig.update_layout(coloraxis_showscale=False)
        plotly(fig)

# ======================================================================
# TAB 2 - REQUEST INSPECTOR
# ======================================================================
with tabs[1]:
    st.subheader("Inspect a request")
    st.caption("Submit a structured request, or paste a raw HTTP request / curl command. "
               "SentinelShield shows the verdict, every rule that fired and how it decoded the input.")

    input_mode = st.radio("Input type", ["Structured form", "Raw HTTP", "curl command"],
                          horizontal=True)

    request = None
    if input_mode == "Structured form":
        cc1, cc2 = st.columns([1, 2])
        with cc1:
            ip = st.text_input("Source IP", "203.0.113.55")
            method = st.selectbox("Method", ["GET", "POST", "PUT", "DELETE", "PATCH"])
            path = st.text_input("Path", "/search")
        with cc2:
            query = st.text_input("Query string", "q=")
            user_agent = st.text_input("User-Agent", "Mozilla/5.0")
            body = st.text_area("Body", "", height=90)
        if st.button("🔎 Inspect request", type="primary"):
            request = detector.build_request(
                method=method, path=path, query=query,
                headers={"User-Agent": user_agent}, body=body, ip=ip)
    elif input_mode == "Raw HTTP":
        raw = st.text_area(
            "Raw HTTP request", height=200,
            value=("GET /search?q=<script>alert(1)</script> HTTP/1.1\n"
                   "Host: shop.example.com\n"
                   "User-Agent: Mozilla/5.0\n"))
        ip = st.text_input("Source IP", "203.0.113.55", key="rawip")
        if st.button("🔎 Inspect request", type="primary"):
            request = detector.parse_raw_http(raw)
            request["ip"] = ip
    else:
        curl = st.text_area(
            "curl command", height=140,
            value="curl 'https://shop.example.com/items?id=1%20OR%201=1' -H 'User-Agent: sqlmap/1.7'")
        ip = st.text_input("Source IP", "203.0.113.55", key="curlip")
        if st.button("🔎 Inspect request", type="primary"):
            request = detector.parse_curl(curl)
            request["ip"] = ip

    if request is not None:
        event = engine.process(request, store=True)
        action = event["action"]
        base = action.split(" (")[0]
        st.divider()
        if base == ALLOWED:
            st.success(f"✅ {action}")
        elif base == FLAGGED:
            st.warning(f"⚠️ {action}")
        elif base == RATE_LIMITED:
            st.warning(f"⏱️ {action}")
        else:
            st.error(f"🚨 {action}")

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Decision", base)
        m2.metric("Category", event["category"])
        m3.metric("Anomaly score", event["score"])
        m4.metric("Severity", event["severity"])
        st.caption(f"Reason: {event['reason']}")

        if event["matches"]:
            st.markdown("#### Rules triggered")
            md = pd.DataFrame([{
                "Rule": m["rule_id"], "Name": m["name"], "Category": m["category"],
                "Severity": m["severity"], "Score": m["score"], "Location": m["location"],
                "Matched": m["matched"], "OWASP": m["owasp"], "CWE": m["cwe"],
            } for m in event["matches"]])
            st.dataframe(md, width="stretch", hide_index=True)

        if event["matches"]:
            tid, tname = intel.mitre_for(event["category"])
            pb = intel.playbook_for(event["category"])
            st.markdown("#### 🛰️ Threat intelligence & response playbook")
            st.markdown(
                f"<span class='ss-badge' style='background:#1e293b;color:#38bdf8;'>MITRE ATT&CK {tid}</span>"
                f"<span class='ss-badge' style='background:#1e293b;color:#e2e8f0;'>{tname}</span>",
                unsafe_allow_html=True,
            )
            st.markdown(f"**Impact:** {pb['impact']}")
            st.markdown(f"**Remediation:** {pb['remediation']}")
            st.markdown(f"**Immediate response:** {pb['response']}")

        with st.expander("🔬 How the input was normalised (evasion decoding)"):
            seg_text = " ".join(
                str(v) for _, v in detector.request_segments(request) if v)
            _, steps = detector.normalize(seg_text)
            if steps:
                st.dataframe(pd.DataFrame(steps), width="stretch", hide_index=True)
            else:
                st.caption("No decoding was necessary for this input.")

# ======================================================================
# TAB 3 - ATTACK SIMULATOR
# ======================================================================
with tabs[2]:
    st.subheader("Attack simulator")
    st.caption("Replay realistic traffic through the engine. Useful for demos and for testing the rules end-to-end.")

    scen_cols = st.columns(3)
    scenario_names = list(SCENARIOS.keys())
    for idx, name in enumerate(scenario_names):
        with scen_cols[idx % 3]:
            if st.button(name, width="stretch", key=f"scn_{idx}"):
                evs = run_scenario(engine, name)
                blocked = sum(1 for e in evs if e["action"].startswith(BLOCKED))
                st.success(f"Ran {len(evs)} requests · {blocked} blocked")

    st.divider()
    if st.button("▶️ Run full test suite (all scenarios)", type="primary"):
        evs = run_all_scenarios(engine)
        rows = [{
            "IP": e["ip_address"], "Method": e["method"], "Path": e["path"],
            "Category": e["category"], "Decision": e["action"].split(" (")[0],
            "Severity": e["severity"], "Score": e["score"],
        } for e in evs]
        st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
        st.success(f"Replayed {len(evs)} requests across {len(SCENARIOS)} scenarios.")

    with st.expander("What each scenario sends"):
        for name, spec in SCENARIOS.items():
            st.markdown(f"**{name}** — source `{spec['ip']}`, {len(spec['requests'])} requests")

# ======================================================================
# TAB 4 - THREAT INTEL
# ======================================================================
with tabs[3]:
    st.subheader("IP reputation & threat intelligence")
    snap = engine.reputation.snapshot()
    if not snap:
        st.info("No IP activity yet. Generate traffic from the simulator or inspector.")
    else:
        rep_df = pd.DataFrame(snap)
        rep_df["ban"] = rep_df.apply(
            lambda r: "permanent" if r["ban_remaining"] == -1
            else (f"{r['ban_remaining'] // 60} min" if r["banned"] else "-"), axis=1)
        rep_df["intel"] = rep_df.apply(
            lambda r: ipintel.enrich(r["ip"], r.to_dict()), axis=1)
        rep_df["risk"] = rep_df["intel"].apply(lambda e: e["risk"])
        rep_df["ip_type"] = rep_df["intel"].apply(lambda e: e["type"])
        show = rep_df[["ip", "ip_type", "risk", "score", "strikes", "bans", "events",
                       "banned", "ban", "allowlisted", "denylisted"]]
        st.dataframe(show, width="stretch", hide_index=True)

        st.markdown("#### 🗂️ Attacker case file (incident reconstruction)")
        ips = rep_df["ip"].tolist()
        chosen = st.selectbox("Select a source IP", ips, key="case_ip")
        if chosen:
            all_events = logger.load_events()
            case = intel.attacker_case_file(all_events, chosen)
            enriched = ipintel.enrich(
                chosen, next((r for r in snap if r["ip"] == chosen), None))
            if case:
                k1, k2, k3, k4 = st.columns(4)
                k1.metric("Threat level", case["threat_level"])
                k2.metric("Malicious / total", f"{case['malicious_requests']}/{case['total_requests']}")
                k3.metric("Techniques", len(case["techniques"]))
                k4.metric("Total score", case["total_score"])
                st.caption(f"IP class: **{enriched['type']}** · {enriched['note']} · "
                           f"First seen {case['first_seen']} → last {case['last_seen']}")
                if case["techniques"]:
                    st.markdown("**MITRE ATT&CK techniques observed**")
                    st.dataframe(pd.DataFrame(case["techniques"]), width="stretch", hide_index=True)
                st.markdown(f"**Recommended response:** {case['recommended_response']}")
                with st.expander("Full request timeline"):
                    st.dataframe(pd.DataFrame(case["timeline"]), width="stretch", hide_index=True)
            else:
                st.caption("No events recorded for this IP yet.")

        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown("**Ban / unban**")
            ip_in = st.text_input("IP address", key="ti_ip")
            if st.button("Ban permanently") and ip_in:
                engine.reputation.ban(ip_in)
                st.rerun()
            if st.button("Unban") and ip_in:
                engine.reputation.unban(ip_in)
                st.rerun()
        with c2:
            st.markdown("**Allowlist**")
            allow_ip = st.text_input("Trusted IP", key="ti_allow")
            if st.button("Add to allowlist") and allow_ip:
                engine.reputation.add_allow(allow_ip)
                st.rerun()
        with c3:
            st.markdown("**Denylist**")
            deny_ip = st.text_input("Blocked IP", key="ti_deny")
            if st.button("Add to denylist") and deny_ip:
                engine.reputation.add_deny(deny_ip)
                st.rerun()

# ======================================================================
# TAB 5 - SECURITY LOGS
# ======================================================================
with tabs[4]:
    st.subheader("Security event log")
    df = events_df()
    if df.empty:
        st.info("No events recorded yet.")
    else:
        f1, f2, f3 = st.columns(3)
        actions = ["All"] + sorted(df["action"].dropna().unique().tolist())
        cats = ["All"] + sorted(df["category"].dropna().unique().tolist())
        sel_action = f1.selectbox("Action", actions)
        sel_cat = f2.selectbox("Category", cats)
        search = f3.text_input("Search (IP / path / request)")

        view = df.copy()
        if sel_action != "All":
            view = view[view["action"] == sel_action]
        if sel_cat != "All":
            view = view[view["category"] == sel_cat]
        if search:
            mask = (
                view["ip_address"].astype(str).str.contains(search, case=False, na=False)
                | view["path"].astype(str).str.contains(search, case=False, na=False)
                | view["request"].astype(str).str.contains(search, case=False, na=False)
            )
            view = view[mask]

        st.caption(f"{len(view)} of {len(df)} events")
        cols = ["timestamp", "ip_address", "method", "path", "category",
                "action", "severity", "score", "request"]
        st.dataframe(view[cols].sort_values("timestamp", ascending=False),
                     width="stretch", hide_index=True)

        d1, d2 = st.columns(2)
        d1.download_button("⬇️ Export CSV", logger.export_csv(view.to_dict("records")),
                           "sentinelshield_events.csv", "text/csv", width="stretch")
        d2.download_button("⬇️ Export JSON", logger.export_json(view.to_dict("records")),
                           "sentinelshield_events.json", "application/json", width="stretch")

# ======================================================================
# TAB 6 - LOG FORENSICS
# ======================================================================
with tabs[5]:
    st.subheader("Access-log forensics")
    st.caption("Upload an Apache/Nginx access log from a server that had no WAF. "
               "SentinelShield replays every line through the detector and reports the attacks it finds.")

    sample_path = os.path.join("data", "sample_access.log")
    log_text = None
    up = st.file_uploader("Upload access.log", type=["log", "txt"])
    if up is not None:
        log_text = up.read().decode("utf-8", errors="replace")
    elif os.path.exists(sample_path) and st.button("Use bundled sample log"):
        with open(sample_path, "r", encoding="utf-8") as fh:
            log_text = fh.read()

    if log_text:
        result = detector.analyze_access_log(log_text)
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Log lines", result["total_lines"])
        c2.metric("Malicious", result["malicious_lines"])
        c3.metric("Unique IPs", result["unique_ips"])
        c4.metric("Brute-force IPs", len(result["brute_force_ips"]))

        if result["category_counts"]:
            cc = pd.DataFrame(result["category_counts"].items(), columns=["category", "count"])
            plotly(px.bar(cc.sort_values("count"), x="count", y="category",
                          orientation="h", color="count", color_continuous_scale="Reds"))
        if result["findings"]:
            st.markdown("#### Attacks found")
            st.dataframe(pd.DataFrame(result["findings"])[
                ["ip", "time", "method", "target", "status", "category", "score", "agent"]],
                width="stretch", hide_index=True)
        if result["top_attackers"]:
            st.markdown("#### Top attackers")
            st.dataframe(pd.DataFrame(result["top_attackers"], columns=["ip", "malicious requests"]),
                         width="stretch", hide_index=True)

# ======================================================================
# TAB 7 - RULES & ACCURACY
# ======================================================================
with tabs[6]:
    st.subheader("Detection rule library")
    rule_rows = []
    for r in rules_mod.DETECTION_RULES:
        tid, tname = intel.mitre_for(r["category"])
        rule_rows.append({
            "ID": r["id"], "Name": r["name"], "Category": r["category"],
            "Severity": r["severity"], "Score": r["score"],
            "OWASP": r["owasp"], "CWE": r["cwe"], "MITRE": tid,
            "Enabled": r.get("enabled", True),
        })
    cat_filter = st.selectbox("Filter by category", ["All"] + rules_mod.CATEGORIES)
    rdf = pd.DataFrame(rule_rows)
    if cat_filter != "All":
        rdf = rdf[rdf["Category"] == cat_filter]
    st.dataframe(rdf, width="stretch", hide_index=True)

    st.markdown("#### MITRE ATT&CK coverage")
    att = pd.DataFrame([{
        "Technique": f"{intel.mitre_for(r['category'])[0]} · {intel.mitre_for(r['category'])[1]}"
    } for r in rules_mod.DETECTION_RULES])
    att_cov = att["Technique"].value_counts().reset_index()
    att_cov.columns = ["Technique", "rules"]
    plotly(px.bar(att_cov.sort_values("rules"), x="rules", y="Technique",
                  orientation="h", color="rules", color_continuous_scale="Purples"))

    st.markdown("#### Live regex tester")
    test_text = st.text_input("Test string", "id=1' OR '1'='1")
    if test_text:
        hits = detector.scan_text(test_text, location="query")
        if hits:
            st.dataframe(pd.DataFrame([{
                "Rule": h["rule_id"], "Name": h["name"], "Category": h["category"],
                "Matched": h["matched"], "Form": h["form"],
            } for h in hits]), width="stretch", hide_index=True)
        else:
            st.success("No rule matched — this input would be ALLOWED.")

    st.divider()
    st.subheader("Detection accuracy (labelled benchmark)")
    b1, b2, b3, b4, b5 = st.columns(5)
    b1.metric("Samples", bench["total"])
    b2.metric("Accuracy", f"{bench['accuracy'] * 100:.1f}%")
    b3.metric("Precision", f"{bench['precision'] * 100:.1f}%")
    b4.metric("Recall", f"{bench['recall'] * 100:.1f}%")
    b5.metric("F1", f"{bench['f1'] * 100:.1f}%")

    cm1, cm2 = st.columns(2)
    with cm1:
        st.markdown("**Confusion matrix (attack vs normal)**")
        cm = pd.DataFrame(
            [[bench["tp"], bench["fn"]], [bench["fp"], bench["tn"]]],
            index=["Actual attack", "Actual normal"],
            columns=["Predicted attack", "Predicted normal"])
        st.table(cm)
    with cm2:
        st.markdown("**False positives / negatives**")
        if not bench["false_positives"] and not bench["false_negatives"]:
            st.success("Zero false positives and zero false negatives on the benchmark corpus.")
        else:
            for fp in bench["false_positives"]:
                st.write(f"FP: `{fp['input']}` → {fp['predicted']}")
            for fn in bench["false_negatives"]:
                st.write(f"FN: `{fn['input']}` (expected {fn['expected']})")

# ======================================================================
# TAB 8 - ALERTS & REPORT
# ======================================================================
with tabs[7]:
    st.subheader("Alert queue")
    alerts = logger.load_alerts()
    open_alerts = [a for a in alerts if not a.get("acknowledged")]
    st.caption(f"{len(open_alerts)} open · {len(alerts)} total")

    if open_alerts:
        if st.button("Acknowledge all"):
            logger.acknowledge_all_alerts()
            st.rerun()
        adf = pd.DataFrame(open_alerts)[
            ["timestamp", "ip_address", "category", "severity", "action", "score", "request"]]
        st.dataframe(adf, width="stretch", hide_index=True)
    else:
        st.success("No open alerts.")

    st.divider()
    st.subheader("Generate security report")
    st.caption("Produces a Markdown report from the live events and the accuracy benchmark — "
               "ready to drop into your practical journal.")
    report = logger.generate_report(benchmark=bench)
    st.download_button("⬇️ Download report (Markdown)", report,
                       f"sentinelshield_report_{datetime.now():%Y%m%d}.md",
                       "text/markdown", type="primary")
    with st.expander("Preview report"):
        st.markdown(report)

# ======================================================================
# TAB 9 - CONFIG & OPS
# ======================================================================
with tabs[8]:
    st.subheader("Configuration")
    st.caption("SentinelShield is configured from a JSON file (`sentinelshield.config.json`) — "
               "thresholds, rate limits, disabled rules, allow/deny lists and custom rules — "
               "so it can be tuned like a real product without editing code.")
    src = loaded_cfg.get("_source", "defaults")
    st.markdown(f"**Active configuration source:** `{src}`")
    if loaded_cfg.get("_error"):
        st.error(loaded_cfg["_error"])
    display_cfg = {k: v for k, v in loaded_cfg.items() if not k.startswith("_")}
    st.json(display_cfg)

    custom = [r for r in rules_mod.DETECTION_RULES if r.get("_custom")]
    disabled = [r["id"] for r in rules_mod.DETECTION_RULES if not r.get("enabled", True)]
    oc1, oc2 = st.columns(2)
    oc1.metric("Custom rules loaded", len(custom))
    oc2.metric("Rules disabled", len(disabled))

    st.divider()
    st.subheader("📈 Metrics export (Prometheus format)")
    st.caption("A monitoring stack (Prometheus / Grafana) could scrape these metrics in production.")
    metrics_text = metrics_mod.prometheus_text(
        reputation_snapshot=engine.reputation.snapshot())
    st.download_button("⬇️ Download metrics", metrics_text,
                       "sentinelshield_metrics.txt", "text/plain")
    with st.expander("Preview metrics"):
        st.code(metrics_text, language="text")

    st.divider()
    st.subheader("🖥️ Headless CLI")
    st.caption("The same engine runs without the dashboard — on a server or in a CI pipeline. "
               "Exit code 1 means a malicious request was detected, so it works as a CI gate.")
    st.code(
        "python cli.py scan \"id=1' OR '1'='1\"\n"
        "python cli.py inspect --curl \"curl 'http://x/?q=<script>alert(1)</script>'\"\n"
        "python cli.py analyze-log data/sample_access.log\n"
        "python cli.py benchmark        # fails CI if accuracy regresses\n"
        "python cli.py simulate --all\n"
        "python cli.py metrics",
        language="bash",
    )
