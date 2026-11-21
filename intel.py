"""
SentinelShield threat intelligence layer.

Maps each detection category to:
  * a MITRE ATT&CK technique (the language real SOC teams use), and
  * a response playbook (impact, remediation and immediate response),

and reconstructs a per-attacker "case file" / kill chain from stored
events so an analyst can triage an incident the way they would in a real
Security Operations Centre.
"""

from collections import Counter

from rules import SEVERITY_ORDER

# ----------------------------------------------------------------------
# MITRE ATT&CK technique mapping
# ----------------------------------------------------------------------
MITRE_MAP = {
    "SQL Injection": ("T1190", "Exploit Public-Facing Application"),
    "Cross-Site Scripting (XSS)": ("T1059.007", "Command & Scripting Interpreter: JavaScript"),
    "Directory Traversal": ("T1083", "File and Directory Discovery"),
    "Local File Inclusion (LFI)": ("T1005", "Data from Local System"),
    "Command Injection": ("T1059", "Command and Scripting Interpreter"),
    "Server-Side Request Forgery (SSRF)": ("T1552.005", "Cloud Instance Metadata API"),
    "Server-Side Template Injection (SSTI)": ("T1059", "Command and Scripting Interpreter"),
    "Log4Shell (JNDI Injection)": ("T1190", "Exploit Public-Facing Application"),
    "XML External Entity (XXE)": ("T1190", "Exploit Public-Facing Application"),
    "NoSQL Injection": ("T1190", "Exploit Public-Facing Application"),
    "CRLF Injection": ("T1557", "Adversary-in-the-Middle"),
    "Automated Scanner": ("T1595.002", "Active Scanning: Vulnerability Scanning"),
    "Sensitive File Probe": ("T1595.003", "Active Scanning: Wordlist Scanning"),
    "Abusive Traffic": ("T1498", "Network Denial of Service"),
    "Brute Force": ("T1110", "Brute Force"),
    "Scanning Behaviour": ("T1595", "Active Scanning"),
    "Banned Source": ("T1190", "Exploit Public-Facing Application"),
}


def mitre_for(category):
    return MITRE_MAP.get(category, ("T1190", "Exploit Public-Facing Application"))


# ----------------------------------------------------------------------
# Response playbooks
# ----------------------------------------------------------------------
PLAYBOOKS = {
    "SQL Injection": {
        "impact": "Database compromise: data theft, authentication bypass, or full data destruction.",
        "remediation": "Use parameterised queries / prepared statements; apply least-privilege DB accounts; validate and canonicalise input.",
        "response": "Block the source IP, review DB logs for the attacker's queries, confirm no data exfiltration, rotate credentials if the query touched auth tables.",
    },
    "Cross-Site Scripting (XSS)": {
        "impact": "Session hijacking, credential theft and defacement by running JavaScript in victims' browsers.",
        "remediation": "Context-aware output encoding, a strict Content-Security-Policy, and HttpOnly/SameSite cookies.",
        "response": "Block the IP, purge any stored payload, invalidate active sessions for affected pages, and audit where the input is reflected.",
    },
    "Directory Traversal": {
        "impact": "Disclosure of files outside the web root (configuration, source, credentials).",
        "remediation": "Resolve and validate canonical paths; serve files from an allow-listed directory only; never pass user input to file APIs.",
        "response": "Block the IP, check which files were requested and whether any returned 200, and confirm no sensitive file was served.",
    },
    "Local File Inclusion (LFI)": {
        "impact": "Reading local system files and, via wrappers/log poisoning, remote code execution.",
        "remediation": "Disable dangerous stream wrappers, allow-list includable files, and keep user input out of file paths.",
        "response": "Block the IP, review access to /etc/*, /proc/* and wrapper usage, and rotate any secrets that may have been read.",
    },
    "Command Injection": {
        "impact": "Arbitrary operating-system command execution — typically full server compromise.",
        "remediation": "Avoid shell calls; use safe argument arrays/exec APIs; strictly allow-list arguments.",
        "response": "Isolate the host, hunt for persistence and outbound connections, rotate all host credentials, and rebuild if compromise is confirmed.",
    },
    "Server-Side Request Forgery (SSRF)": {
        "impact": "Access to internal services and cloud metadata — a common path to stealing cloud credentials.",
        "remediation": "Allow-list outbound hosts, block link-local/metadata ranges, and require IMDSv2 on cloud instances.",
        "response": "Block the IP, check whether 169.254.169.254 was reached, and rotate any cloud instance credentials immediately.",
    },
    "Server-Side Template Injection (SSTI)": {
        "impact": "Server-side code execution through the template engine.",
        "remediation": "Never render user input as a template; use a sandboxed, logic-less template engine.",
        "response": "Block the IP, audit template rendering paths, and treat the host as potentially compromised.",
    },
    "Log4Shell (JNDI Injection)": {
        "impact": "Unauthenticated remote code execution via logged JNDI lookups (CVE-2021-44228).",
        "remediation": "Patch Log4j to a fixed version; set log4j2.formatMsgNoLookups=true; remove the JndiLookup class.",
        "response": "Treat as critical: block the IP, patch immediately, and hunt for outbound LDAP/RMI callbacks and post-exploitation activity.",
    },
    "XML External Entity (XXE)": {
        "impact": "Local file disclosure, SSRF and denial of service through XML parsing.",
        "remediation": "Disable external entity and DTD processing in every XML parser.",
        "response": "Block the IP, review XML endpoints, and confirm no local files were disclosed.",
    },
    "NoSQL Injection": {
        "impact": "Authentication bypass and data theft against document databases.",
        "remediation": "Validate types, reject query operators in user input, and use an ODM with strict schemas.",
        "response": "Block the IP, review database queries, and confirm no authentication bypass occurred.",
    },
    "CRLF Injection": {
        "impact": "HTTP response splitting, header injection and cache poisoning.",
        "remediation": "Strip CR/LF from any value placed into response headers.",
        "response": "Block the IP and audit endpoints that echo input into headers or redirects.",
    },
    "Automated Scanner": {
        "impact": "Reconnaissance that precedes a targeted attack.",
        "remediation": "Rate-limit and challenge automated clients; hide version banners and error detail.",
        "response": "Block or tarpit the IP and watch for follow-up exploitation from the same source or ASN.",
    },
    "Sensitive File Probe": {
        "impact": "Discovery of configuration, backup or source-control files that leak secrets.",
        "remediation": "Return 404 for dotfiles and backups; keep .git/.env and backups out of the web root.",
        "response": "Block the IP, confirm none of the probed files are reachable, and rotate any exposed secret.",
    },
    "Abusive Traffic": {
        "impact": "Service degradation or denial of service through request flooding.",
        "remediation": "Enforce rate limiting and connection limits; front the app with a CDN where possible.",
        "response": "Rate-limit or temporarily ban the IP and monitor for distributed sources.",
    },
    "Brute Force": {
        "impact": "Account takeover through repeated credential guessing.",
        "remediation": "Lockouts, rate limits, CAPTCHA after N failures, and multi-factor authentication.",
        "response": "Block the IP, force a password reset on targeted accounts, and enable MFA.",
    },
    "Scanning Behaviour": {
        "impact": "Mapping of the application's attack surface before exploitation.",
        "remediation": "Rate-limit per IP and alert on high path-diversity bursts.",
        "response": "Block the IP and correlate with any exploitation attempts that follow.",
    },
}

DEFAULT_PLAYBOOK = {
    "impact": "Potentially malicious request.",
    "remediation": "Validate and canonicalise all input; apply least privilege.",
    "response": "Review the event and block the source if the pattern repeats.",
}


def playbook_for(category):
    return PLAYBOOKS.get(category, DEFAULT_PLAYBOOK)


# ----------------------------------------------------------------------
# Per-attacker incident case file (kill-chain reconstruction)
# ----------------------------------------------------------------------
def attacker_case_file(events, ip):
    """
    Build an incident case file for a single source IP from stored events:
    timeline, techniques used, categories, severity escalation and a
    recommended response.
    """
    ip_events = [e for e in events if e.get("ip_address") == ip]
    if not ip_events:
        return None

    ip_events = sorted(ip_events, key=lambda e: e.get("timestamp", ""))
    malicious = [e for e in ip_events if e.get("category") not in ("", "Normal")]
    categories = Counter(e.get("category") for e in malicious)
    actions = Counter(e.get("action", "").split(" (")[0] for e in ip_events)

    techniques = []
    seen = set()
    for e in malicious:
        cat = e.get("category")
        tid, tname = mitre_for(cat)
        if tid not in seen:
            seen.add(tid)
            techniques.append({"technique": tid, "name": tname, "via": cat})

    top_category = categories.most_common(1)[0][0] if categories else None
    worst_severity = max(
        (e.get("severity", "Low") for e in ip_events),
        key=lambda s: SEVERITY_ORDER.get(s, 0),
        default="Low",
    )
    total_score = sum(int(e.get("score", 0) or 0) for e in ip_events)

    # Threat level from behaviour and score.
    if actions.get("BANNED") or total_score >= 30:
        threat_level = "Critical"
    elif total_score >= 12 or len(categories) >= 3:
        threat_level = "High"
    elif malicious:
        threat_level = "Medium"
    else:
        threat_level = "Low"

    recommended = playbook_for(top_category)["response"] if top_category else \
        "No malicious activity from this IP; continue monitoring."

    return {
        "ip": ip,
        "first_seen": ip_events[0].get("timestamp"),
        "last_seen": ip_events[-1].get("timestamp"),
        "total_requests": len(ip_events),
        "malicious_requests": len(malicious),
        "distinct_categories": len(categories),
        "categories": dict(categories),
        "techniques": techniques,
        "actions": dict(actions),
        "worst_severity": worst_severity,
        "total_score": total_score,
        "threat_level": threat_level,
        "top_category": top_category,
        "recommended_response": recommended,
        "timeline": [
            {
                "timestamp": e.get("timestamp"),
                "method": e.get("method", ""),
                "path": e.get("path", ""),
                "category": e.get("category"),
                "action": e.get("action"),
                "severity": e.get("severity"),
                "score": e.get("score", 0),
            }
            for e in ip_events
        ],
    }
