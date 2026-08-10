from urllib.parse import urlparse, unquote
import ipaddress
import re

from app.data.suspicious_keywords import SUSPICIOUS_KEYWORDS


# ============================================================
# SUSPICIOUS TLDs
# ============================================================

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
    ".cf",
}


# ============================================================
# URL SHORTENER DOMAINS
# ============================================================

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
}


# ============================================================
# SUSPICIOUS PATH / QUERY TERMS
# ============================================================

SUSPICIOUS_PATH_KEYWORDS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "password",
    "credential",
    "authenticate",
    "authentication",
    "reset",
    "confirm",
    "payment",
    "billing",
    "wallet",
    "bank",
    "security",
    "unlock",
    "claim",
}


# ============================================================
# SUSPICIOUS QUERY PARAMETERS
# ============================================================

SUSPICIOUS_QUERY_PARAMETERS = {
    "password",
    "passwd",
    "pass",
    "otp",
    "pin",
    "cvv",
    "card",
    "creditcard",
    "account",
    "verify",
    "verification",
    "token",
    "auth",
    "session",
}


def extract_features(url):
    """
    Extract security-related features from a URL.

    The extractor intentionally collects signals only.
    Final risk scoring is handled by risk_engine.py.
    """

    # ========================================================
    # BASIC NORMALIZATION
    # ========================================================

    original_url = url.strip()
    url_lower = original_url.lower()

    parsed_url = urlparse(original_url)

    hostname = (
        parsed_url.hostname or ""
    ).lower()

    path = (
        parsed_url.path or ""
    ).lower()

    query = (
        parsed_url.query or ""
    ).lower()

    fragment = (
        parsed_url.fragment or ""
    ).lower()

    decoded_url = unquote(
        url_lower
    )

    # ========================================================
    # 1. SUSPICIOUS KEYWORDS
    # ========================================================

    matched_keywords = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword.lower() in decoded_url
    ]

    # Remove duplicates while preserving order
    matched_keywords = list(
        dict.fromkeys(matched_keywords)
    )

    # ========================================================
    # 2. IP ADDRESS DETECTION
    # ========================================================

    is_ip_address = False

    try:
        ipaddress.ip_address(hostname)
        is_ip_address = True
    except ValueError:
        pass

    # ========================================================
    # 3. SUSPICIOUS TLD
    # ========================================================

    suspicious_tld = any(
        hostname.endswith(tld)
        for tld in SUSPICIOUS_TLDS
    )

    # ========================================================
    # 4. HYphen COUNT
    # ========================================================

    hyphen_count = hostname.count("-")

    # ========================================================
    # 5. SUBDOMAIN COUNT
    # ========================================================

    subdomain_count = 0

    if hostname and not is_ip_address:

        parts = hostname.split(".")

        if len(parts) > 2:
            subdomain_count = len(parts) - 2

    # ========================================================
    # 6. URL SHORTENER
    # ========================================================

    is_shortened_url = (
        hostname in SHORTENER_DOMAINS
    )

    # ========================================================
    # 7. SUSPICIOUS PATH KEYWORDS
    # ========================================================

    matched_path_keywords = [
        keyword
        for keyword in SUSPICIOUS_PATH_KEYWORDS
        if keyword in path
    ]

    matched_path_keywords = list(
        dict.fromkeys(
            matched_path_keywords
        )
    )

    # ========================================================
    # 8. SUSPICIOUS QUERY PARAMETERS
    # ========================================================

    query_parameters = set()

    if query:

        for parameter in query.split("&"):

            parameter_name = (
                parameter.split("=")[0]
                .strip()
                .lower()
            )

            if parameter_name:
                query_parameters.add(
                    parameter_name
                )

    matched_query_parameters = [
        parameter
        for parameter in query_parameters
        if parameter in SUSPICIOUS_QUERY_PARAMETERS
    ]

    # ========================================================
    # 9. QUERY PARAMETER COUNT
    # ========================================================

    query_parameter_count = len(
        query_parameters
    )

    # ========================================================
    # 10. HAS FRAGMENT
    # ========================================================

    has_fragment = bool(fragment)

    # ========================================================
    # 11. HAS @ SYMBOL
    # ========================================================

    has_at_symbol = "@" in original_url

    # ========================================================
    # 12. ENCODED / OBFUSCATED URL
    # ========================================================

    has_encoded_characters = bool(
        re.search(
            r"%[0-9a-fA-F]{2}",
            original_url
        )
    )

    # ========================================================
    # 13. PUNYCODE DOMAIN
    # ========================================================

    uses_punycode = (
        "xn--" in hostname
    )

    # ========================================================
    # 14. DOMAIN LENGTH
    # ========================================================

    hostname_length = len(
        hostname
    )

    # ========================================================
    # 15. LONG URL
    # ========================================================

    url_length = len(
        original_url
    )

    # ========================================================
    # 16. DIGIT COUNT IN HOSTNAME
    # ========================================================

    digit_count_in_hostname = sum(
        character.isdigit()
        for character in hostname
    )

    # ========================================================
    # 17. DIGIT-HEAVY DOMAIN
    # ========================================================

    digit_heavy_domain = (
        digit_count_in_hostname >= 4
        and not is_ip_address
    )

    # ========================================================
    # 18. REPEATED SEPARATORS
    # ========================================================

    has_repeated_separators = bool(
        re.search(
            r"[-_.]{2,}",
            hostname
        )
    )

    # ========================================================
    # 19. SUSPICIOUS PATH
    # ========================================================

    has_suspicious_path = (
        len(matched_path_keywords) > 0
    )

    # ========================================================
    # 20. SUSPICIOUS QUERY
    # ========================================================

    has_suspicious_query = (
        len(matched_query_parameters) > 0
    )

    # ========================================================
    # FINAL FEATURE DICTIONARY
    # ========================================================

    features = {

        # Basic
        "url_length": url_length,
        "is_https": (
            parsed_url.scheme.lower()
            == "https"
        ),

        "dot_count": original_url.count("."),

        # Keywords
        "keyword_count": len(
            matched_keywords
        ),

        "matched_keywords": matched_keywords,

        # Network / domain
        "is_ip_address": is_ip_address,

        "hostname": hostname,

        "hostname_length": hostname_length,

        "digit_count_in_hostname":
            digit_count_in_hostname,

        "digit_heavy_domain":
            digit_heavy_domain,

        # URL structure
        "has_at_symbol": has_at_symbol,

        "hyphen_count": hyphen_count,

        "subdomain_count":
            subdomain_count,

        "suspicious_tld":
            suspicious_tld,

        "is_shortened_url":
            is_shortened_url,

        # Path
        "matched_path_keywords":
            matched_path_keywords,

        "path_keyword_count":
            len(matched_path_keywords),

        "has_suspicious_path":
            has_suspicious_path,

        # Query
        "query_parameter_count":
            query_parameter_count,

        "matched_query_parameters":
            matched_query_parameters,

        "has_suspicious_query":
            has_suspicious_query,

        # Fragment
        "has_fragment":
            has_fragment,

        # Obfuscation
        "has_encoded_characters":
            has_encoded_characters,

        "uses_punycode":
            uses_punycode,

        "has_repeated_separators":
            has_repeated_separators,
    }

    return features