"""
Offline IP intelligence for SentinelShield.

Uses only the Python standard library (``ipaddress``) to classify a
source address without any paid GeoIP/threat feed. It identifies
loopback, private, carrier-grade NAT, link-local, documentation,
reserved and multicast ranges, and combines that with the IP's observed
behaviour (strikes, bans, anomaly score) into a single risk verdict.

This is deliberately honest: it does not claim geolocation it cannot
know offline. It classifies what the address *is* and what it has *done*.
"""

import ipaddress

# Well-known hosting/VPN-adjacent ranges are intentionally NOT hard-coded
# (that needs a live feed). We classify structure + observed behaviour.


def classify_address(ip):
    """Return structural facts about an IP address string."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "type": "unknown", "version": None,
                "note": "Not a valid IP address (hostname or malformed)."}

    kind = "public"
    note = "Routable public address."
    # Membership checks that don't rely on is_private (which varies by
    # Python version for CGNAT and documentation ranges).
    cgnat = addr.version == 4 and addr in ipaddress.ip_network("100.64.0.0/10")
    doc_ranges = ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"]
    is_doc = False
    for net in doc_ranges:
        try:
            if addr in ipaddress.ip_network(net):
                is_doc = True
                break
        except ValueError:
            continue

    if addr.is_loopback:
        kind, note = "loopback", "Loopback address (the server itself)."
    elif addr.is_link_local:
        kind, note = "link-local", "Link-local address; also used for cloud metadata (169.254.0.0/16)."
    elif cgnat:
        kind, note = "cgnat", "Carrier-grade NAT (shared ISP address, 100.64.0.0/10)."
    elif is_doc:
        kind, note = "documentation", "Documentation/example range (RFC 5737/3849) — test traffic."
    elif addr.is_multicast:
        kind, note = "multicast", "Multicast address (should never be a client source)."
    elif addr.is_unspecified:
        kind, note = "unspecified", "Unspecified address (0.0.0.0 / ::)."
    elif addr.is_private:
        kind, note = "private", "Private/internal network address (RFC 1918 / ULA)."
    elif addr.is_reserved:
        kind, note = "reserved", "Reserved address space."

    return {
        "ip": ip,
        "type": kind,
        "version": f"IPv{addr.version}",
        "global": bool(addr.is_global),
        "note": note,
    }


def enrich(ip, reputation_entry=None):
    """
    Combine structural classification with observed behaviour into a
    single risk verdict (Benign / Suspicious / Malicious / Blocked).
    ``reputation_entry`` is a row from IPReputation.snapshot().
    """
    base = classify_address(ip)
    rep = reputation_entry or {}
    strikes = int(rep.get("strikes", 0) or 0)
    score = int(rep.get("score", 0) or 0)
    banned = bool(rep.get("banned", False))
    bans = int(rep.get("bans", 0) or 0)

    reasons = [base["note"]]
    risk = "Benign"

    if base["type"] in ("loopback", "private", "link-local", "cgnat"):
        reasons.append("Non-public source — unusual for external attack traffic.")

    if banned:
        risk = "Blocked"
        reasons.append(f"Currently banned (ban events: {bans}).")
    elif strikes >= 3 or score >= 12:
        risk = "Malicious"
        reasons.append(f"High offence history (strikes={strikes}, score={score}).")
    elif strikes >= 1 or score >= 3:
        risk = "Suspicious"
        reasons.append(f"Some malicious activity (strikes={strikes}, score={score}).")

    if base["type"] == "documentation":
        reasons.append("Documentation range — typically simulated/test traffic.")

    return {
        **base,
        "risk": risk,
        "strikes": strikes,
        "score": score,
        "banned": banned,
        "reasons": reasons,
    }
