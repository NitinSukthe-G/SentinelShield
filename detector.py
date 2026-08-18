import re
from rules import DETECTION_RULES


def detect_threat(text):
    """
    Inspect request data and identify known attack patterns.
    Returns the detected category and matched rule.
    """

    if not text:
        return {
            "detected": False,
            "category": "Normal",
            "matched_rule": None
        }

    for category, patterns in DETECTION_RULES.items():
        for pattern in patterns:
            if re.search(pattern, text):
                return {
                    "detected": True,
                    "category": category,
                    "matched_rule": pattern
                }

    return {
        "detected": False,
        "category": "Normal",
        "matched_rule": None
    }