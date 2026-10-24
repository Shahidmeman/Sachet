
import re
from urllib.parse import urlparse


# Known brands for demonstration purposes only.
# This is not a complete or authoritative list.
KNOWN_BRANDS = [
    "sbi.co.in",
    "hdfcbank.com",
    "icicibank.com",
    "axisbank.com",
    "indiapost.gov.in",
    "bluedart.com",
    "dhl.com",
]

URL_PATTERN = re.compile(
    r"""(?i)\b(?:https?://|www\.)[^\s<>"']+"""
)

PHONE_PATTERN = re.compile(
    r"(?<!\w)(?:\+91[\s-]?)?[6-9]\d{9}(?!\w)"
)

UPI_PATTERN = re.compile(
    r"(?i)\b[a-z0-9._-]{2,256}@[a-z][a-z0-9]{1,63}\b"
)

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "rb.gy",
}

URGENCY_TERMS = [
    "immediately",
    "urgent",
    "within 24 hours",
    "expires today",
    "account blocked",
    "act now",
    "final warning",
    "immediate action",
]

PAYMENT_TERMS = [
    "pay now",
    "payment required",
    "processing fee",
    "release fee",
    "send money",
    "upi payment",
]

CREDENTIAL_TERMS = [
    "share otp",
    "enter your otp",
    "password",
    "pin",
    "cvv",
    "verify your kyc",
]


def extract_urls(text):
    """Extract URLs written explicitly in the message."""
    return URL_PATTERN.findall(text)


def extract_phone_numbers(text):
    """Extract phone numbers matching a basic Indian mobile pattern."""
    return PHONE_PATTERN.findall(text)


def extract_upi_ids(text):
    """Find strings that resemble UPI IDs; these are not verified."""
    return UPI_PATTERN.findall(text)


def inspect_url(raw_url):
    """Return explainable URL signals without visiting the URL."""
    candidate = raw_url.rstrip(".,!?;:)[]}")

    if candidate.lower().startswith("www."):
        candidate = "https://" + candidate

    parsed = urlparse(candidate)
    hostname = (parsed.hostname or "").lower().rstrip(".")

    evidence = []

    if not hostname:
        return {
            "url": raw_url,
            "hostname": None,
            "signals": ["Could not parse hostname"],
        }

    if parsed.scheme == "http":
        evidence.append("Uses unencrypted HTTP")

    if hostname in SHORTENERS:
        evidence.append("Uses a known URL-shortening domain")

    if hostname.startswith("xn--") or ".xn--" in hostname:
        evidence.append("Contains a punycode label")

    if hostname.count(".") >= 3:
        evidence.append("Has an unusually deep subdomain structure")

    # Exact known-domain matching avoids treating arbitrary
    # substrings as legitimate brands.
    for brand in KNOWN_BRANDS:
        if hostname == brand or hostname.endswith("." + brand):
            break
    else:
        # Do not call every unknown domain malicious.
        evidence.append("Domain is not on the small demonstration allowlist")

    return {
        "url": raw_url,
        "hostname": hostname,
        "signals": evidence,
    }


def analyze_message(text):
    """
    Score technical and textual warning signals.
    This is a heuristic, not a calibrated probability.
    """
    normalized = text.lower()
    evidence = []
    score = 0

    urls = extract_urls(text)
    phones = extract_phone_numbers(text)
    upi_ids = extract_upi_ids(text)

    inspected_urls = [inspect_url(url) for url in urls]

    for item in inspected_urls:
        for signal in item["signals"]:
            evidence.append(
                f"URL signal for {item['hostname']}: {signal}"
            )

            if signal == "Uses a known URL-shortening domain":
                score += 25
            elif signal == "Uses unencrypted HTTP":
                score += 15
            elif signal == "Contains a punycode label":
                score += 25
            elif signal == "Domain is not on the small demonstration allowlist":
                score += 5
            elif signal == "Has an unusually deep subdomain structure":
                score += 10

    urgency_found = [
        term for term in URGENCY_TERMS if term in normalized
    ]

    payment_found = [
        term for term in PAYMENT_TERMS if term in normalized
    ]

    credentials_found = [
        term for term in CREDENTIAL_TERMS if term in normalized
    ]

    if urgency_found:
        score += 15
        evidence.append(
            "Urgency language detected: " + ", ".join(urgency_found)
        )

    if payment_found:
        score += 20
        evidence.append(
            "Payment-related language detected: "
            + ", ".join(payment_found)
        )

    if credentials_found:
        score += 25
        evidence.append(
            "Credential or sensitive-information language detected: "
            + ", ".join(credentials_found)
        )

    if upi_ids:
        evidence.append(
            "UPI-like identifier(s) found: " + ", ".join(upi_ids)
        )

    if phones:
        evidence.append(
            "Phone number(s) found: " + ", ".join(phones)
        )

    score = min(score, 100)

    if score >= 50:
        verdict = "Likely scam"
    elif score >= 20:
        verdict = "Suspicious"
    else:
        verdict = "No obvious warning signals detected"

    return {
        "verdict": verdict,
        "risk_score": score,
        "evidence": evidence,
        "urls": inspected_urls,
        "phone_numbers": phones,
        "upi_ids": upi_ids,
        "disclaimer": (
            "This heuristic score is not a probability or guarantee. "
            "A low score does not mean a message is safe."
        ),
    }
