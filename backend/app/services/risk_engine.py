def calculate_risk(features):
    """
    Calculate scam risk score from extracted URL features.

    Risk Levels:
        0-29   -> SAFE
        30-59  -> SUSPICIOUS
        60-79  -> HIGH RISK
        80-100 -> CRITICAL
    """

    score = 0
    reasons = []

    # ============================================================
    # 1. Suspicious Keywords
    # ============================================================

    matched_keywords = features.get(
        "matched_keywords",
        []
    )

    unique_keywords = list(
        dict.fromkeys(
            str(keyword).lower()
            for keyword in matched_keywords
        )
    )

    keyword_count = len(unique_keywords)

    if keyword_count > 0:

        # Do not over-reward multiple keywords.
        keyword_score = min(
            keyword_count * 5,
            15
        )

        score += keyword_score

        for keyword in unique_keywords:
            reasons.append(
                f"Suspicious keyword detected: {keyword}"
            )

    # ============================================================
    # 2. Authentication / Phishing Combination
    # ============================================================

    phishing_keywords = {
        "login",
        "signin",
        "sign-in",
        "verify",
        "verification",
        "account",
        "password",
        "credential",
        "secure",
        "authenticate",
        "authentication",
    }

    phishing_matches = (
        set(unique_keywords)
        & phishing_keywords
    )

    if len(phishing_matches) >= 2:

        score += 15

        reasons.append(
            "Multiple authentication or account-verification "
            "indicators detected"
        )

    # ============================================================
    # 3. HTTPS
    # ============================================================

    is_https = features.get(
        "is_https",
        False
    )

    if not is_https:

        score += 10

        reasons.append(
            "URL does not use HTTPS"
        )

    # ============================================================
    # 4. Suspicious TLD
    # ============================================================

    if features.get(
        "suspicious_tld",
        False
    ):

        score += 15

        reasons.append(
            "Suspicious top-level domain detected"
        )

    # ============================================================
    # 5. IP Address
    # ============================================================

    if features.get(
        "is_ip_address",
        False
    ):

        score += 20

        reasons.append(
            "URL uses an IP address instead of a domain"
        )

    # ============================================================
    # 6. @ Symbol
    # ============================================================

    if features.get(
        "has_at_symbol",
        False
    ):

        score += 20

        reasons.append(
            "URL contains @ symbol which can disguise "
            "the actual destination"
        )

    # ============================================================
    # 7. Multiple Hyphens
    # ============================================================

    hyphen_count = features.get(
        "hyphen_count",
        0
    )

    if hyphen_count >= 3:

        score += 8

        reasons.append(
            "Domain contains multiple hyphens"
        )

    # ============================================================
    # 8. Multiple Subdomains
    # ============================================================

    subdomain_count = features.get(
        "subdomain_count",
        0
    )

    if subdomain_count >= 2:

        score += 8

        reasons.append(
            "URL contains multiple subdomains"
        )

    # ============================================================
    # 9. URL Shortener
    # ============================================================

    if features.get(
        "is_shortened_url",
        False
    ):

        score += 20

        reasons.append(
            "URL uses a URL shortening service"
        )

    # ============================================================
    # 10. Very Long URL
    # ============================================================

    url_length = features.get(
        "url_length",
        0
    )

    if url_length > 100:

        score += 8

        reasons.append(
            "URL is unusually long"
        )

    # ============================================================
    # 11. Suspicious Path
    # ============================================================

    matched_path_keywords = features.get(
        "matched_path_keywords",
        []
    )

    unique_path_keywords = list(
        dict.fromkeys(
            str(keyword).lower()
            for keyword in matched_path_keywords
        )
    )

    path_keyword_count = len(
        unique_path_keywords
    )

    if path_keyword_count > 0:

        # Path is supporting evidence,
        # not another full keyword score.
        score += 5

        for keyword in unique_path_keywords:
            reasons.append(
                f"Suspicious path indicator: {keyword}"
            )

    # ============================================================
    # 12. Suspicious Query Parameters
    # ============================================================

    matched_query_parameters = features.get(
        "matched_query_parameters",
        []
    )

    unique_query_parameters = list(
        dict.fromkeys(
            str(parameter).lower()
            for parameter in matched_query_parameters
        )
    )

    query_parameter_count = len(
        unique_query_parameters
    )

    if query_parameter_count > 0:

        # Supporting evidence only.
        query_score = min(
            query_parameter_count * 5,
            10
        )

        score += query_score

        for parameter in unique_query_parameters:
            reasons.append(
                f"Sensitive query parameter detected: {parameter}"
            )

    # ============================================================
    # 13. Encoded / Obfuscated URL
    # ============================================================

    if features.get(
        "has_encoded_characters",
        False
    ):

        score += 8

        reasons.append(
            "URL contains encoded characters that may "
            "obscure its destination"
        )

    # ============================================================
    # 14. Punycode
    # ============================================================

    if features.get(
        "uses_punycode",
        False
    ):

        score += 20

        reasons.append(
            "Domain uses Punycode which can be used "
            "for look-alike domains"
        )

    # ============================================================
    # 15. Digit-Heavy Domain
    # ============================================================

    if features.get(
        "digit_heavy_domain",
        False
    ):

        score += 8

        reasons.append(
            "Domain contains an unusually high number "
            "of digits"
        )

    # ============================================================
    # 16. Repeated Separators
    # ============================================================

    if features.get(
        "has_repeated_separators",
        False
    ):

        score += 8

        reasons.append(
            "Domain contains repeated separators"
        )

    # ============================================================
    # 17. Excessive Query Parameters
    # ============================================================

    total_query_parameters = features.get(
        "query_parameter_count",
        0
    )

    if total_query_parameters >= 5:

        score += 8

        reasons.append(
            "URL contains an unusually large number "
            "of query parameters"
        )

    # ============================================================
    # 18. Long Hostname
    # ============================================================

    hostname_length = features.get(
        "hostname_length",
        0
    )

    if hostname_length > 60:

        score += 8

        reasons.append(
            "Domain name is unusually long"
        )

    # ============================================================
    # 19. Multi-Signal Bonus
    # ============================================================

    # Count independent categories, not every individual
    # keyword/path/query signal.
    independent_signals = 0

    if keyword_count > 0:
        independent_signals += 1

    if not is_https:
        independent_signals += 1

    if features.get(
        "suspicious_tld",
        False
    ):
        independent_signals += 1

    if features.get(
        "is_ip_address",
        False
    ):
        independent_signals += 1

    if features.get(
        "has_at_symbol",
        False
    ):
        independent_signals += 1

    if hyphen_count >= 3:
        independent_signals += 1

    if subdomain_count >= 2:
        independent_signals += 1

    if features.get(
        "is_shortened_url",
        False
    ):
        independent_signals += 1

    if path_keyword_count > 0:
        independent_signals += 1

    if query_parameter_count > 0:
        independent_signals += 1

    if features.get(
        "uses_punycode",
        False
    ):
        independent_signals += 1

    if features.get(
        "has_encoded_characters",
        False
    ):
        independent_signals += 1

    # Moderate bonus only.
    if independent_signals >= 4:

        score += 5

        reasons.append(
            "Multiple independent suspicious URL indicators "
            "were detected together"
        )

    # ============================================================
    # 20. Strong Authentication Combination
    # ============================================================

    authentication_path = (
        path_keyword_count > 0
        and len(phishing_matches) >= 1
    )

    sensitive_query = (
        query_parameter_count > 0
    )

    # This is stronger because three different categories
    # agree with each other.
    if (
        authentication_path
        and sensitive_query
        and not is_https
    ):

        score += 10

        reasons.append(
            "Authentication-related path, sensitive query "
            "parameters, and insecure HTTP detected together"
        )

    # ============================================================
    # 21. High-Risk Structural Combination
    # ============================================================

    high_risk_structural_signals = 0

    if features.get(
        "is_ip_address",
        False
    ):
        high_risk_structural_signals += 1

    if features.get(
        "has_at_symbol",
        False
    ):
        high_risk_structural_signals += 1

    if features.get(
        "uses_punycode",
        False
    ):
        high_risk_structural_signals += 1

    if features.get(
        "is_shortened_url",
        False
    ):
        high_risk_structural_signals += 1

    if features.get(
        "has_encoded_characters",
        False
    ):
        high_risk_structural_signals += 1

    if features.get(
        "suspicious_tld",
        False
    ):
        high_risk_structural_signals += 1

    if high_risk_structural_signals >= 3:

        score += 15

        reasons.append(
            "Several high-risk structural indicators "
            "were detected together"
        )

    # ============================================================
    # 22. Critical Risk Override
    # ============================================================

    # CRITICAL should require genuinely strong evidence.
    critical_evidence = 0

    if features.get(
        "is_ip_address",
        False
    ):
        critical_evidence += 1

    if features.get(
        "has_at_symbol",
        False
    ):
        critical_evidence += 1

    if features.get(
        "uses_punycode",
        False
    ):
        critical_evidence += 1

    if features.get(
        "is_shortened_url",
        False
    ):
        critical_evidence += 1

    if features.get(
        "suspicious_tld",
        False
    ):
        critical_evidence += 1

    if features.get(
        "has_encoded_characters",
        False
    ):
        critical_evidence += 1

    if len(phishing_matches) >= 2:
        critical_evidence += 1

    if query_parameter_count >= 2:
        critical_evidence += 1

    if not is_https:
        critical_evidence += 1

    # At least 5 strong signals are required.
    if critical_evidence >= 5:

        score = max(
            score,
            80
        )

        reasons.append(
            "Multiple strong phishing and structural "
            "risk indicators detected"
        )

    # ============================================================
    # 23. Keep Score Between 0-100
    # ============================================================

    score = min(
        max(score, 0),
        100
    )

    # ============================================================
    # 24. Final Verdict
    # ============================================================

    if score >= 80:

        verdict = "CRITICAL"

    elif score >= 60:

        verdict = "HIGH RISK"

    elif score >= 30:

        verdict = "SUSPICIOUS"

    else:

        verdict = "SAFE"

    # ============================================================
    # 25. Safe Explanation
    # ============================================================

    if score < 30 and not reasons:

        reasons.append(
            "No significant suspicious URL indicators detected"
        )

    # ============================================================
    # 26. Final Result
    # ============================================================

    return {
        "risk_score": score,
        "verdict": verdict,
        "reasons": reasons
    }