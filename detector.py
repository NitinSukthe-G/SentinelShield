"""
SentinelShield inspection engine.

This module turns raw request data into security verdicts. It:

  * normalises input the way attackers try to hide payloads
    (URL encoding, HTML entities, unicode tricks, SQL comments);
  * inspects every part of an HTTP request (method, path, query,
    headers, cookies, body), not just a single field;
  * returns every rule that matched, where it matched, and a combined
    anomaly score (OWASP CRS style);
  * parses raw HTTP requests, curl commands and web-server access logs;
  * measures its own accuracy against a labelled benchmark corpus.
"""

import html
import re
import unicodedata
import urllib.parse
from collections import Counter

from rules import (
    BENCHMARK_CORPUS,
    DETECTION_RULES,
    SEVERITY_ORDER,
)

MAX_SNIPPET = 120


# ----------------------------------------------------------------------
# Normalisation
# ----------------------------------------------------------------------
def normalize(text):
    """
    Decode common evasion encodings and return the canonical form plus
    the list of transformation steps that changed the text.

    Returns (normalized_text, steps) where steps is a list of
    {"step", "before", "after"} describing each change.
    """
    if text is None:
        return "", []

    steps = []
    current = str(text)

    def _record(step, new_value):
        nonlocal current
        if new_value != current:
            steps.append(
                {
                    "step": step,
                    "before": _clip(current),
                    "after": _clip(new_value),
                }
            )
            current = new_value

    # Recursive percent-decoding (handles double/triple encoding).
    for i in range(3):
        decoded = urllib.parse.unquote_plus(current)
        if decoded == current:
            break
        _record(f"URL-decode (pass {i + 1})", decoded)

    # HTML entity decoding (&lt; &#60; &#x3c;).
    _record("HTML-entity decode", html.unescape(current))

    # Unicode compatibility normalisation (full-width -> ASCII, etc.).
    _record("Unicode NFKC", unicodedata.normalize("NFKC", current))

    # Strip null bytes used to truncate strings.
    _record("Strip null bytes", current.replace("\x00", "").replace("%00", ""))

    # Remove inline SQL comments used to split keywords: UNION/**/SELECT.
    _record("Strip SQL comments", re.sub(r"/\*.*?\*/", " ", current, flags=re.DOTALL))

    # Collapse runs of whitespace so "or    1=1" matches "or 1=1".
    _record("Collapse whitespace", re.sub(r"\s+", " ", current).strip())

    return current, steps


def _clip(value):
    value = str(value)
    return value if len(value) <= MAX_SNIPPET else value[:MAX_SNIPPET] + "..."


# ----------------------------------------------------------------------
# Request model
# ----------------------------------------------------------------------
def build_request(
    method="GET",
    path="/",
    query="",
    headers=None,
    cookies=None,
    body="",
    ip="",
):
    """Create the normalised request dict the engine inspects."""
    return {
        "method": (method or "GET").upper(),
        "path": path or "/",
        "query": query or "",
        "headers": headers or {},
        "cookies": cookies or {},
        "body": body or "",
        "ip": ip or "",
    }


def request_segments(request):
    """
    Yield (location, value) pairs for every inspectable part of a
    request. Location strings look like 'query', 'header.User-Agent' or
    'cookie.session'.
    """
    yield ("path", request.get("path", ""))
    yield ("query", request.get("query", ""))
    yield ("body", request.get("body", ""))
    for name, value in (request.get("headers") or {}).items():
        yield (f"header.{name}", value)
    for name, value in (request.get("cookies") or {}).items():
        yield (f"cookie.{name}", value)


def _target_matches(rule, location):
    targets = rule.get("targets", ["any"])
    if "any" in targets:
        return True
    base = location.split(".", 1)[0]
    name = location.split(".", 1)[1].lower() if "." in location else ""
    for target in targets:
        target = target.lower()
        if target == base:
            return True
        if target == "user-agent" and base == "header" and name == "user-agent":
            return True
        if target == "path" and base in ("path", "query"):
            return True
    return False


# ----------------------------------------------------------------------
# Core detection
# ----------------------------------------------------------------------
def scan_text(text, location="input", rules=None):
    """
    Run all enabled rules against one string (raw and normalised) and
    return a list of match dicts.
    """
    rules = rules if rules is not None else DETECTION_RULES
    if not text:
        return []

    raw = str(text)
    normalized, _ = normalize(raw)
    matches = []
    seen = set()

    for rule in rules:
        if not rule.get("enabled", True):
            continue
        if not _target_matches(rule, location):
            continue

        stage = rule.get("stage", "both")
        candidates = []
        if stage in ("raw", "both"):
            candidates.append(("raw", raw))
        if stage in ("normalized", "both"):
            candidates.append(("normalized", normalized))

        for form, value in candidates:
            m = rule["regex"].search(value)
            if not m:
                continue
            key = (rule["id"], location)
            if key in seen:
                break
            seen.add(key)
            matches.append(
                {
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "score": rule["score"],
                    "location": location,
                    "form": form,
                    "matched": _clip(m.group(0)),
                    "owasp": rule["owasp"],
                    "cwe": rule["cwe"],
                }
            )
            break

    return matches


def inspect_request(request, rules=None):
    """
    Inspect a full request and return a verdict:

        {
          "detected": bool,
          "score": int,
          "category": str,        # primary (highest-severity) category
          "severity": str,
          "matches": [...],       # every rule hit, with location
          "categories": [...],    # distinct categories seen
          "locations": [...],     # distinct locations that triggered
        }
    """
    all_matches = []
    for location, value in request_segments(request):
        all_matches.extend(scan_text(value, location=location, rules=rules))

    if not all_matches:
        return {
            "detected": False,
            "score": 0,
            "category": "Normal",
            "severity": "Low",
            "matches": [],
            "categories": [],
            "locations": [],
        }

    score = sum(m["score"] for m in all_matches)
    primary = max(
        all_matches,
        key=lambda m: (SEVERITY_ORDER.get(m["severity"], 0), m["score"]),
    )
    categories = list(dict.fromkeys(m["category"] for m in all_matches))
    locations = list(dict.fromkeys(m["location"] for m in all_matches))

    return {
        "detected": True,
        "score": score,
        "category": primary["category"],
        "severity": primary["severity"],
        "matches": all_matches,
        "categories": categories,
        "locations": locations,
    }


def detect_threat(text):
    """
    Backward-compatible single-string detector (matches the original
    SentinelShield API). Returns detected flag, category and matched rule.
    """
    matches = scan_text(text, location="input")
    if not matches:
        return {"detected": False, "category": "Normal", "matched_rule": None}
    primary = max(
        matches, key=lambda m: (SEVERITY_ORDER.get(m["severity"], 0), m["score"])
    )
    return {
        "detected": True,
        "category": primary["category"],
        "matched_rule": primary["rule_id"],
        "matches": matches,
        "score": sum(m["score"] for m in matches),
    }


# ----------------------------------------------------------------------
# Request parsing: raw HTTP and curl
# ----------------------------------------------------------------------
def _split_path_query(target):
    if "?" in target:
        path, query = target.split("?", 1)
    else:
        path, query = target, ""
    return path or "/", query


def parse_raw_http(raw):
    """Parse a pasted raw HTTP request into a request dict."""
    text = (raw or "").replace("\r\n", "\n").strip("\n")
    if not text:
        return build_request()

    lines = text.split("\n")
    method, path, query = "GET", "/", ""
    first = lines[0].split()
    if len(first) >= 2 and first[0].isalpha() and first[0].isupper():
        method = first[0]
        path, query = _split_path_query(first[1])

    headers, cookies = {}, {}
    body_start = len(lines)
    for idx in range(1, len(lines)):
        line = lines[idx]
        if line == "":
            body_start = idx + 1
            break
        if ":" in line:
            name, _, value = line.partition(":")
            name, value = name.strip(), value.strip()
            headers[name] = value
            if name.lower() == "cookie":
                cookies.update(_parse_cookies(value))

    body = "\n".join(lines[body_start:]) if body_start < len(lines) else ""
    return build_request(method, path, query, headers, cookies, body)


def _parse_cookies(cookie_header):
    jar = {}
    for part in cookie_header.split(";"):
        if "=" in part:
            name, _, value = part.partition("=")
            jar[name.strip()] = value.strip()
    return jar


def parse_curl(command):
    """Parse a curl command line into a request dict (best effort)."""
    import shlex

    text = (command or "").strip()
    if not text:
        return build_request()
    text = re.sub(r"\\\s*\n", " ", text)
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:
        tokens = text.split()

    method, url, body = None, None, ""
    headers, cookies = {}, {}
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("curl",):
            i += 1
            continue
        if tok in ("-X", "--request") and i + 1 < len(tokens):
            method = tokens[i + 1].upper()
            i += 2
            continue
        if tok in ("-H", "--header") and i + 1 < len(tokens):
            name, _, value = tokens[i + 1].partition(":")
            name, value = name.strip(), value.strip()
            if name:
                headers[name] = value
                if name.lower() == "cookie":
                    cookies.update(_parse_cookies(value))
            i += 2
            continue
        if tok in ("-b", "--cookie") and i + 1 < len(tokens):
            cookies.update(_parse_cookies(tokens[i + 1]))
            i += 2
            continue
        if tok in ("-d", "--data", "--data-raw", "--data-binary", "--data-urlencode") and i + 1 < len(tokens):
            body = (body + "&" + tokens[i + 1]) if body else tokens[i + 1]
            i += 2
            continue
        if tok in ("-A", "--user-agent") and i + 1 < len(tokens):
            headers["User-Agent"] = tokens[i + 1]
            i += 2
            continue
        if tok in ("-e", "--referer") and i + 1 < len(tokens):
            headers["Referer"] = tokens[i + 1]
            i += 2
            continue
        if tok.startswith("-"):
            # Skip unknown flags; skip their value if they take one.
            if i + 1 < len(tokens) and not tokens[i + 1].startswith("-") and tok not in ("-s", "-k", "-v", "-L", "-i", "-sS"):
                i += 2
            else:
                i += 1
            continue
        if url is None:
            url = tok
        i += 1

    path, query = "/", ""
    if url:
        parsed = urllib.parse.urlsplit(url if "://" in url else "http://" + url)
        path = parsed.path or "/"
        query = parsed.query
    if method is None:
        method = "POST" if body else "GET"
    return build_request(method, path, query, headers, cookies, body)


# ----------------------------------------------------------------------
# Access-log forensics
# ----------------------------------------------------------------------
_LOG_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+(?P<proto>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)


def parse_access_log(text):
    """Parse Apache/Nginx combined-format log lines into dicts."""
    entries = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        m = _LOG_RE.match(line)
        if not m:
            continue
        d = m.groupdict()
        entries.append(
            {
                "ip": d["ip"],
                "time": d["time"],
                "method": d["method"],
                "target": d["target"],
                "status": int(d["status"]),
                "referer": d.get("referer") or "",
                "agent": d.get("agent") or "",
            }
        )
    return entries


def analyze_access_log(text):
    """
    Run the detector over every log line and summarise the attacks,
    attackers and scanners found.
    """
    entries = parse_access_log(text)
    findings = []
    attacker_counter = Counter()
    category_counter = Counter()
    login_hits = Counter()

    for entry in entries:
        path, query = _split_path_query(entry["target"])
        request = build_request(
            method=entry["method"],
            path=path,
            query=query,
            headers={"User-Agent": entry["agent"], "Referer": entry["referer"]},
            ip=entry["ip"],
        )
        verdict = inspect_request(request)
        if re.search(r"/(?:login|signin|admin|auth|wp-login)", path, re.IGNORECASE):
            login_hits[entry["ip"]] += 1
        if verdict["detected"]:
            findings.append(
                {
                    "ip": entry["ip"],
                    "time": entry["time"],
                    "method": entry["method"],
                    "target": entry["target"],
                    "status": entry["status"],
                    "agent": entry["agent"],
                    "category": verdict["category"],
                    "score": verdict["score"],
                    "categories": verdict["categories"],
                }
            )
            attacker_counter[entry["ip"]] += 1
            for cat in verdict["categories"]:
                category_counter[cat] += 1

    brute_force = {ip: n for ip, n in login_hits.items() if n >= 10}

    return {
        "total_lines": len(entries),
        "malicious_lines": len(findings),
        "findings": findings,
        "top_attackers": attacker_counter.most_common(10),
        "category_counts": dict(category_counter),
        "brute_force_ips": brute_force,
        "unique_ips": len({e["ip"] for e in entries}),
    }


# ----------------------------------------------------------------------
# Accuracy benchmark
# ----------------------------------------------------------------------
def evaluate_corpus(corpus=None):
    """
    Measure detection quality against the labelled corpus. Returns
    accuracy, precision, recall, F1 and the false positive / negative
    lists (binary attack-vs-normal classification).
    """
    corpus = corpus if corpus is not None else BENCHMARK_CORPUS
    tp = tn = fp = fn = 0
    false_positives = []
    false_negatives = []
    category_correct = 0
    category_total = 0
    rows = []

    for text, expected in corpus:
        verdict = detect_threat(text)
        predicted = verdict["category"] if verdict["detected"] else "Normal"
        expected_attack = expected != "Normal"
        predicted_attack = predicted != "Normal"

        if expected_attack and predicted_attack:
            tp += 1
            category_total += 1
            if predicted == expected:
                category_correct += 1
        elif not expected_attack and not predicted_attack:
            tn += 1
        elif not expected_attack and predicted_attack:
            fp += 1
            false_positives.append({"input": text, "predicted": predicted})
        else:
            fn += 1
            false_negatives.append({"input": text, "expected": expected})

        rows.append(
            {
                "input": text,
                "expected": expected,
                "predicted": predicted,
                "correct": predicted_attack == expected_attack,
            }
        )

    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    cat_accuracy = category_correct / category_total if category_total else 0.0

    return {
        "total": total,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "category_accuracy": cat_accuracy,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "rows": rows,
    }
