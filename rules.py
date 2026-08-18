# SentinelShield Detection Rules

DETECTION_RULES = {
    "SQL Injection": [
        r"(?i)(union\s+select)",
        r"(?i)(or\s+1\s*=\s*1)",
        r"(?i)(and\s+1\s*=\s*1)",
        r"(?i)(select\s+.*\s+from\s+)",
        r"(?i)(drop\s+table)",
        r"(?i)(insert\s+into\s+)",
        r"(?i)(delete\s+from\s+)",
    ],

    "Cross-Site Scripting (XSS)": [
        r"(?i)(<script[^>]*>)",
        r"(?i)(javascript\s*:)",
        r"(?i)(onerror\s*=)",
        r"(?i)(onload\s*=)",
    ],

    "Directory Traversal": [
        r"(\.\./)",
        r"(\.\.\\)",
        r"(?i)(%2e%2e%2f)",
        r"(?i)(%2e%2e/)",
    ],

    "Local File Inclusion (LFI)": [
        r"(?i)(/etc/passwd)",
        r"(?i)(etc/passwd)",
        r"(?i)(boot\.ini)",
        r"(?i)(file://)",
    ],

    "Command Injection": [
        r"(?i)(;\s*whoami)",
        r"(?i)(;\s*id\b)",
        r"(?i)(\|\s*whoami)",
        r"(?i)(\|\s*id\b)",
        r"(?i)(&&\s*whoami)",
        r"(?i)(&&\s*id\b)",
    ],
}