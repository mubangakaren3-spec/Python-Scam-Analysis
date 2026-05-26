"""
detector_core.py — Shared scam detection logic for Zambian Scam Detector.
Loads patterns and thresholds dynamically from patterns.yaml with static fallbacks.
"""

import os
import re
import yaml

# Path to patterns config file
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "patterns.yaml")

# -------------------------------------------------------------------
# Static Fallback Configurations (in case patterns.yaml is missing)
# -------------------------------------------------------------------
DEFAULT_RISK_THRESHOLDS = {
    "SAFE": {"min_score": 0, "max_score": 0, "color": "green"},
    "LOW RISK": {"min_score": 1, "max_score": 4, "color": "yellow"},
    "MODERATE RISK": {"min_score": 5, "max_score": 9, "color": "orange"},
    "HIGH RISK": {"min_score": 10, "max_score": 14, "color": "red"},
    "EXTREME RISK": {"min_score": 15, "max_score": None, "color": "darkred"},
}

DEFAULT_ESCALATION_RULES = {
    "min_flags": 3,
    "target_score": 10
}

DEFAULT_SCAM_PATTERNS = [
    # Airtel Money
    (r'\bairtel\b.*\bsuspended\b',                          5,  "Airtel scam detected"),
    (r'\bairtel\b.*\bverify\b',                             5,  "Airtel scam detected"),
    (r'\bairtel\b.*\bupdated?\b',                           4,  "Airtel scam detected"),

    # MTN
    (r'\bmtn\b.*\bsuspended\b',                             5,  "MTN scam detected"),
    (r'\bmtn\b.*\bverify\b',                                5,  "MTN scam detected"),
    (r'\bmtn\b.*\bexpired\b.*\bupdate\b',                   5,  "MTN scam detected"),

    # Bank / phishing
    (r'\bsuspended\b.*\bverify\b',                          5,  "Bank phishing detected"),
    (r'\bcompromised\b.*\bverify\b',                        5,  "Bank phishing detected"),
    (r'\bverify\b.*\bimmediately\b.*\b(lose|suspended)\b',  5,  "Bank phishing detected"),
    (r'(?=.*\bzanaco\b)(?=.*\bsuspended\b)',                          5,  "Bank phishing detected"),
    (r'(?=.*\bfnb\b)(?=.*\b(verify|expire|update)\b)',                      5,  "Bank phishing detected"),
    (r'(?=.*\b(account|bank)\b)(?=.*\b(suspended|expire|compromised)\b)(?=.*\b(verify|update|information)\b)', 5, "Bank phishing detected"),

    # Prize / lottery
    (r'\bcongratulations\b.*\b(won|win)\b.*\b(claim|click)\b', 5, "Prize scam detected"),
    (r'\blottery\b.*\b(winner|won|claim)\b',                5,  "Prize scam detected"),
    (r'(?=.*\b(won|win)\b)(?=.*\blottery\b)\b',                         5,  "Prize scam detected"),
    (r'\bprize\b.*\b(claim|click)\b',                       4,  "Prize scam detected"),
    (r'\bwin\b.*\bfree\b.*\b(trip|prize|cash)\b',           5,  "Prize scam detected"),
    (r'\bselected\b.*\bk\d+',                               4,  "Prize scam detected"),
    (r'\bfree\b.*\bcash\b',                                 3,  "Prize scam detected"),
    (r'\bfree\b.*\btrip\b.*\b(claim|click)\b',              5,  "Prize scam detected"),
    (r'(?=.*\b(donate|donation)\b)(?=.*\b(help|emergency)\b)',        5,  "Prize scam detected"),

    # Job offer
    (r'\bwork from home\b.*\bearn\b.*\bweekly\b.*\bno experience\b', 5, "Job offer scam detected"),
    (r'\bjob\b.*\bpay.*training\b',                         5,  "Job offer scam detected"),
    (r'\bearn\b.*\bk\d+.*\bweekly\b.*\bno experience\b',   5,  "Job offer scam detected"),
    (r'\bno experience\b.*\bhigh pay\b',                    4,  "Job offer scam detected"),
    (r'(?=.*\bregister\b)(?=.*\bjob\b)\b',                                3,  "Job offer scam detected"),

    # Investment
    (r'(?=.*\binvest\b)(?=.*\bguaranteed\b)\b',                           5,  "Investment scam detected"),
    (r'\bbitcoin\b.*\bdouble\b',                            5,  "Investment scam detected"),
    (r'\bforex\b.*\bprofit\b',                              4,  "Investment scam detected"),
    (r'\bmake money\b.*\bfast\b',                           3,  "Investment scam detected"),
    (r'\breturns?\b.*\b\d+%\b',                             4,  "Investment scam detected"),

    # Emergency / help
    (r'\bstranded\b.*\bsend\b',                             4,  "Emergency scam detected"),
    (r'\bemergency\b.*\b(money|send)\b',                    4,  "Emergency scam detected"),
    (r'\bhospital\b.*\bneed\b',                             3,  "Emergency scam detected"),
    (r'(?=.*\bhelp\b)(?=.*\bairtime\b)\b',                                3,  "Emergency scam detected"),
    (r'(?=.*\bphone\b)(?=.*\b(broken|lost|stolen)\b)',                       3,  "Emergency scam detected"),
    (r'(?=.*\bsend\b)(?=.*\bairtime\b)\b',                                3,  "Emergency scam detected"),
    (r'\bwithdraw\b.*\bk\d+\b',                             4,  "Emergency scam detected"),
    (r'(?=.*\bwithdraw\b)(?=.*\bemergency\b)',                        4,  "Emergency scam detected"),
    (r'(?=.*\b(urgently|immediately|urgent)\b)(?=.*k\d+)',          5,  "Emergency payment request"),

    # Romance
    (r'\bhello dear\b.*\b(send|money|help)\b',              4,  "Romance scam detected"),
    (r'\bdear\b.*\b(send|money|flight|ticket)\b',           4,  "Romance scam detected"),
    (r'(?=.*\blove\b)(?=.*\b(send|money)\b)',                           4,  "Romance scam detected"),
    (r'\bloving you\b.*\b(help|send|money)\b',              4,  "Romance scam detected"),
    (r'\bsoldier\b.*\b(money|send)\b',                      4,  "Romance scam detected"),
    (r'(?=.*\b(flight|ticket|visa)\b)(?=.*\bsend\b)(?=.*\bmoney\b)\b',        4,  "Romance scam detected"),
    (r'\binterested.*you\b.*\b(send|money)\b',              4,  "Romance scam detected"),

    # Delivery / customs
    (r'\bpackage\b.*\bcustoms\b.*\b(pay|fee)\b.*\b(release|claim)\b.*\b(now|urgent|immediately|link|click|transfer)\b', 5, "Delivery scam detected"),
    (r'(?=.*\b(package|parcel|customs)\b)(?=.*\b(held|pending|pay|fee)\b)(?=.*\b(release|claim|customs|custom|pay)\b)', 5, "Delivery scam detected"),
    (r'(?=.*\b(dhl|fedex|ups)\b)(?=.*\b(pending|released|held)\b)(?=.*\b(pay|fee)\b)', 5, "Delivery scam detected"),
    (r'(?=.*\bcasino\b)(?=.*\b(win|visit|big)\b)',                          5,  "Generic betting/casino scam"),

    # Payment requests
    (r'(?=.*\bsend\b)(?=.*\bmoney\b)(?=.*\b(urgently|immediately|now)\b)',  4,  "Payments request detected"),
    (r'(?=.*\btransfer\b)(?=.*\bk\d+\b)',                               3,  "Payments request detected"),
    (r'(?=.*\bairtime\b)(?=.*\b(need|send)\b)',                     3,  "Payments request detected"),
    (r'(?=.*\bpay\b)(?=.*\bfee\b)(?=.*\b(now|urgently|immediately|stranger)\b)', 4, "Payments request detected"),
    (r'(?=.*\bdeposit\b)(?=.*\baccount\b)',                         3,  "Payments request detected"),

    # Fake transaction receipts
    (r'(?=.*\breceived\b)(?=.*\b(zmw|k)\s*\d+(?:\s*[.,]\s*\d{2})?\b)(?=.*\bdial\s*\*[\d*#]+\b)',     10,  "Fake receipt scam detected"),
    
    # Fake loans
    (r'(?=.*\b(loan|credit)\b)(?=.*\b(zmw|k)\s*\d+(?:\s*[.,]\s*\d{2})?\b)(?=.*\bdial\s*\*[\d*#]+\b)', 10, "Fake loan scam detected"),

    # Generic flags / USSD format / Amount formatting
    (r'(?=.*\b(zmw|k)\s*\d+(?:\s*[.,]\s*\d{2})?\b)(?=.*\bfrom\b)',           3,  "Suspicious money notification"),
    (r'\bdial\s*\*[\d*#]+',                                         3,  "Suspicious USSD dial request"),
    (r'\btid\s*:\s*[a-z0-9.]+',                             3,  "Suspicious transaction ID format"),
    (r'(?=.*\bselected\b)(?=.*\b(survey|offer|promo|gift|win)\b)', 5, "Suspicious phishing lead"),
]

# Initialize with static fallbacks first
risk_thresholds = DEFAULT_RISK_THRESHOLDS
escalation_rules = DEFAULT_ESCALATION_RULES
scam_patterns = DEFAULT_SCAM_PATTERNS

# Try to load from patterns.yaml
if os.path.exists(CONFIG_PATH):
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
            if config:
                if "risk_thresholds" in config:
                    risk_thresholds = config["risk_thresholds"]
                if "escalation_rules" in config:
                    escalation_rules = config["escalation_rules"]
                if "patterns" in config:
                    scam_patterns = [
                        (p["pattern"], p["weight"], p["label"])
                        for p in config["patterns"]
                        if "pattern" in p and "weight" in p and "label" in p
                    ]
    except Exception as e:
        print(f"[WARN] Failed to load patterns.yaml: {e}. Using static fallbacks.")


def get_risk_level(score: int) -> tuple[str, str]:
    """
    Convert a numeric score to a (risk_label, colour) tuple based on configuration.
    """
    for label, limits in risk_thresholds.items():
        min_s = limits.get("min_score", 0)
        max_s = limits.get("max_score")
        
        if max_s is None:
            if score >= min_s:
                return label, limits.get("color", "white")
        else:
            if min_s <= score <= max_s:
                return label, limits.get("color", "white")
                
    return "UNKNOWN", "white"


def get_advice(score: int, flags: list[str]) -> list[str]:
    """
    Return Zambian-specific safety advice lines for a given score/flags.
    """
    if score == 0:
        return [
            "No obvious scam indicators detected.",
            "However, always verify the sender through official channels.",
            "Contact the company directly using their official number.",
        ]

    advice = ["WARNING: This message shows signs of a scam!", ""]
    flags_text = " ".join(flags).lower()

    if "airtel" in flags_text or "mtn" in flags_text:
        advice += [
            "MOBILE MONEY SAFETY:",
            " . NEVER share your mobile money PIN",
            " . Airtel: Call 888 | MTN: Call 303 to verify",
            " . Check account via official app only",
            "",
        ]

    if "bank" in flags_text or "zanaco" in flags_text:
        advice += [
            "BANK SAFETY:",
            " . Banks NEVER ask for passwords via SMS/email",
            " . Visit your branch in person if concerned",
            " . Never click links in suspicious messages",
            "",
        ]

    if "payment" in flags_text:
        advice += [
            "PAYMENT WARNING:",
            " . NEVER send money to strangers",
            " . Legitimate companies do not demand gift cards",
            " . If too good to be true, it is",
            "",
        ]

    advice += [
        "PROTECT YOURSELF:",
        " . Report to Zambia Police Cyber Crime Unit",
        " . Report to ZICTA (www.zicta.zm)",
        " . Share with family and friends",
    ]
    return advice


class ScamDetector:
    """
    Core scam detector. Analyses free-text messages and returns a
    (score, flags) tuple. Use get_risk_level() and get_advice() for
    human-readable output.
    """

    def __init__(self):
        # Pre-compile all patterns for performance
        self._compiled = [
            (re.compile(pattern, re.IGNORECASE | re.DOTALL), weight, label)
            for pattern, weight, label in scam_patterns
        ]

    def analyze(self, text: str) -> tuple[int, list[str]]:
        """
        Analyse a message and return (score, flags).

        Args:
            text: Raw message text.

        Returns:
            score: Cumulative risk score.
            flags: List of triggered category labels.
        """
        score = 0
        flags: list[str] = []
        text_lower = text.lower()

        for compiled_pattern, weight, label in self._compiled:
            if compiled_pattern.search(text_lower):
                score += weight
                flags.append(label)

        # Escalation Rule dynamically from configuration
        min_flags = escalation_rules.get("min_flags", 3)
        target_score = escalation_rules.get("target_score", 10)
        if len(flags) >= min_flags and score < target_score:
            score = target_score

        return score, flags

    def get_risk_level(self, score: int) -> tuple[str, str]:
        """Delegate to module-level helper (kept for backwards compat)."""
        return get_risk_level(score)

    def get_advice(self, score: int, flags: list[str]) -> list[str]:
        """Delegate to module-level helper (kept for backwards compat)."""
        return get_advice(score, flags)
