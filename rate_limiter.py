"""
SentinelShield behaviour monitoring and IP reputation.

Beyond single-request signatures, real attacks show up in *behaviour*:
floods of requests, repeated login attempts, and scanners that touch
many different paths. This module tracks that behaviour per source IP
and maintains an escalating reputation / auto-ban system.

A clock function can be injected so the time-window logic is fully
testable without real waiting.
"""

import json
import os
import threading
import time
from collections import defaultdict, deque

IP_STATE_FILE = "data/ip_state.json"

# Escalating ban ladder: each additional ban lasts longer.
BAN_LADDER = [
    5 * 60,        # 5 minutes
    30 * 60,       # 30 minutes
    6 * 60 * 60,   # 6 hours
    24 * 60 * 60,  # 24 hours
]
PERMANENT = -1


class RateLimiter:
    """Sliding-window request-rate limiter (per IP)."""

    def __init__(self, max_requests=10, window_seconds=60, clock=time.time):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.request_history = defaultdict(deque)
        self._clock = clock

    def _trim(self, ip):
        now = self._clock()
        q = self.request_history[ip]
        while q and now - q[0] > self.window_seconds:
            q.popleft()
        return q

    def check_request(self, ip_address):
        q = self._trim(ip_address)
        if len(q) >= self.max_requests:
            return {
                "allowed": False,
                "reason": "Rate limit exceeded",
                "request_count": len(q),
            }
        q.append(self._clock())
        return {
            "allowed": True,
            "reason": "Request allowed",
            "request_count": len(q),
        }

    def current_rate(self, ip_address):
        return len(self._trim(ip_address))


class BehaviorMonitor:
    """
    Detects abusive behaviour over a sliding window:
      * flooding            (RateLimiter)
      * login brute force   (many auth-path hits)
      * scanning            (many distinct paths or attack categories)
    """

    AUTH_RE = None  # compiled lazily to avoid importing re at module top twice

    def __init__(
        self,
        rate_max=10,
        rate_window=60,
        brute_force_max=5,
        brute_force_window=60,
        scan_path_threshold=15,
        scan_window=60,
        clock=time.time,
    ):
        import re

        self._clock = clock
        self.rate_limiter = RateLimiter(rate_max, rate_window, clock=clock)
        self.brute_force_max = brute_force_max
        self.brute_force_window = brute_force_window
        self.scan_path_threshold = scan_path_threshold
        self.scan_window = scan_window
        self._login_hits = defaultdict(deque)
        self._paths = defaultdict(deque)
        self._auth_re = re.compile(
            r"/(?:login|signin|sign-in|admin|auth|oauth|wp-login|session|token)",
            re.IGNORECASE,
        )

    def record(self, ip, path="/", is_auth=None):
        """
        Register a request and return behaviour findings:
            {"rate_limited": bool, "brute_force": bool,
             "scanning": bool, "request_count": int, "distinct_paths": int}
        """
        now = self._clock()
        rate = self.rate_limiter.check_request(ip)

        if is_auth is None:
            is_auth = bool(self._auth_re.search(path or ""))

        if is_auth:
            hits = self._login_hits[ip]
            hits.append(now)
            while hits and now - hits[0] > self.brute_force_window:
                hits.popleft()
            brute_force = len(hits) >= self.brute_force_max
        else:
            brute_force = False

        paths = self._paths[ip]
        paths.append((now, path or "/"))
        while paths and now - paths[0][0] > self.scan_window:
            paths.popleft()
        distinct_paths = len({p for _, p in paths})
        scanning = distinct_paths >= self.scan_path_threshold

        return {
            "rate_limited": not rate["allowed"],
            "brute_force": brute_force,
            "scanning": scanning,
            "request_count": rate["request_count"],
            "distinct_paths": distinct_paths,
        }


class IPReputation:
    """
    Per-IP threat scoring with an escalating auto-ban ladder plus manual
    allow / deny lists. State is persisted to a JSON file so bans survive
    an app restart.
    """

    def __init__(self, state_file=IP_STATE_FILE, clock=time.time, persist=True):
        self.state_file = state_file
        self._clock = clock
        self._persist = persist
        self._lock = threading.Lock()
        self.ips = {}            # ip -> {score, strikes, bans, banned_until, last_seen, events}
        self.allowlist = set()
        self.denylist = set()
        self._load()

    # -- persistence ---------------------------------------------------
    def _load(self):
        if not (self._persist and os.path.exists(self.state_file)):
            return
        try:
            with open(self.state_file, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self.ips = data.get("ips", {})
            self.allowlist = set(data.get("allowlist", []))
            self.denylist = set(data.get("denylist", []))
        except (json.JSONDecodeError, OSError):
            self.ips = {}

    def _save(self):
        if not self._persist:
            return
        os.makedirs(os.path.dirname(self.state_file) or ".", exist_ok=True)
        tmp = self.state_file + ".tmp"
        payload = {
            "ips": self.ips,
            "allowlist": sorted(self.allowlist),
            "denylist": sorted(self.denylist),
        }
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        os.replace(tmp, self.state_file)

    # -- helpers -------------------------------------------------------
    def _entry(self, ip):
        return self.ips.setdefault(
            ip,
            {
                "score": 0,
                "strikes": 0,
                "bans": 0,
                "banned_until": 0,
                "last_seen": 0,
                "events": 0,
            },
        )

    def is_allowlisted(self, ip):
        return ip in self.allowlist

    def is_denylisted(self, ip):
        return ip in self.denylist

    def is_banned(self, ip):
        if ip in self.denylist:
            return True
        entry = self.ips.get(ip)
        if not entry:
            return False
        until = entry.get("banned_until", 0)
        if until == PERMANENT:
            return True
        return until > self._clock()

    def ban_remaining(self, ip):
        entry = self.ips.get(ip)
        if not entry:
            return 0
        until = entry.get("banned_until", 0)
        if until == PERMANENT:
            return PERMANENT
        remaining = until - self._clock()
        return int(remaining) if remaining > 0 else 0

    # -- state changes -------------------------------------------------
    def record(self, ip, score=0, blocked=False):
        """
        Update reputation after processing a request. Returns the updated
        entry including whether the IP is now banned.
        """
        with self._lock:
            entry = self._entry(ip)
            entry["last_seen"] = int(self._clock())
            entry["events"] += 1
            entry["score"] += score

            newly_banned = False
            if blocked and ip not in self.allowlist:
                entry["strikes"] += 1
                if entry["strikes"] % 3 == 0:
                    self._apply_ban(ip, entry)
                    newly_banned = True

            self._save()
            result = dict(entry)
            result["banned"] = self.is_banned(ip)
            result["newly_banned"] = newly_banned
            return result

    def _apply_ban(self, ip, entry):
        idx = entry["bans"]
        if idx >= len(BAN_LADDER):
            entry["banned_until"] = PERMANENT
        else:
            entry["banned_until"] = int(self._clock()) + BAN_LADDER[idx]
        entry["bans"] += 1

    def ban(self, ip, duration=None):
        """Manually ban an IP for `duration` seconds (None = permanent)."""
        with self._lock:
            entry = self._entry(ip)
            entry["banned_until"] = PERMANENT if duration is None else int(self._clock()) + duration
            entry["bans"] += 1
            self._save()

    def unban(self, ip):
        with self._lock:
            entry = self.ips.get(ip)
            if entry:
                entry["banned_until"] = 0
                entry["strikes"] = 0
            self.denylist.discard(ip)
            self._save()

    def add_allow(self, ip):
        with self._lock:
            self.allowlist.add(ip)
            self.denylist.discard(ip)
            entry = self.ips.get(ip)
            if entry:
                entry["banned_until"] = 0
            self._save()

    def add_deny(self, ip):
        with self._lock:
            self.denylist.add(ip)
            self.allowlist.discard(ip)
            self._save()

    def remove_allow(self, ip):
        with self._lock:
            self.allowlist.discard(ip)
            self._save()

    def remove_deny(self, ip):
        with self._lock:
            self.denylist.discard(ip)
            self._save()

    def snapshot(self):
        """Return a list of per-IP reputation rows for the dashboard."""
        rows = []
        for ip, entry in self.ips.items():
            rows.append(
                {
                    "ip": ip,
                    "score": entry.get("score", 0),
                    "strikes": entry.get("strikes", 0),
                    "bans": entry.get("bans", 0),
                    "events": entry.get("events", 0),
                    "banned": self.is_banned(ip),
                    "ban_remaining": self.ban_remaining(ip),
                    "allowlisted": ip in self.allowlist,
                    "denylisted": ip in self.denylist,
                    "last_seen": entry.get("last_seen", 0),
                }
            )
        rows.sort(key=lambda r: (r["banned"], r["score"]), reverse=True)
        return rows

    def reset(self):
        with self._lock:
            self.ips = {}
            self.allowlist = set()
            self.denylist = set()
            if self._persist and os.path.exists(self.state_file):
                try:
                    os.remove(self.state_file)
                except OSError:
                    pass
