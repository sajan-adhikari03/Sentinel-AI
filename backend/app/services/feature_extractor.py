from urllib.parse import urlparse
import ipaddress

from app.data.suspicious_keywords import SUSPICIOUS_KEYWORDS


SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".click",
    ".work",
    ".loan",
    ".zip",
    ".tk",
    ".ml",
    ".ga",
    ".cf"
}


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly"
}


def extract_features(url):
    """
    Extract security-related features from a URL.
    """

    parsed_url = urlparse(url)
    url_lower = url.lower()

    hostname = parsed_url.hostname or ""

    # --------------------------------
    # 1. Suspicious Keywords
    # --------------------------------
    matched_keywords = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword.lower() in url_lower
    ]

    # --------------------------------
    # 2. IP Address Detection
    # --------------------------------
    is_ip_address = False

    try:
        ipaddress.ip_address(hostname)
        is_ip_address = True
    except ValueError:
        pass

    # --------------------------------
    # 3. Suspicious TLD Detection
    # --------------------------------
    suspicious_tld = any(
        hostname.endswith(tld)
        for tld in SUSPICIOUS_TLDS
    )

    # --------------------------------
    # 4. Hyphen Count
    # --------------------------------
    hyphen_count = url.count("-")

    # --------------------------------
    # 5. Subdomain Count
    # --------------------------------
    subdomain_count = 0

    # IP addresses should NOT be counted
    # as domains/subdomains.
    if hostname and not is_ip_address:
        parts = hostname.split(".")

        if len(parts) > 2:
            subdomain_count = len(parts) - 2

    # --------------------------------
    # 6. URL Shortener Detection
    # --------------------------------
    is_shortened_url = hostname in SHORTENER_DOMAINS

    # --------------------------------
    # 7. Final Feature Dictionary
    # --------------------------------
    features = {
        "url_length": len(url),
        "is_https": parsed_url.scheme.lower() == "https",
        "dot_count": url.count("."),
        "keyword_count": len(matched_keywords),
        "matched_keywords": matched_keywords,
        "is_ip_address": is_ip_address,
        "has_at_symbol": "@" in url,
        "hyphen_count": hyphen_count,
        "subdomain_count": subdomain_count,
        "suspicious_tld": suspicious_tld,
        "is_shortened_url": is_shortened_url
    }

    return features