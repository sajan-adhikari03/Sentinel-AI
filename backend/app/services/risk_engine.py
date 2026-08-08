def calculate_risk(features):
    """
    Calculate scam risk score from extracted URL features.
    """

    score = 0
    reasons = []

    # --------------------------------
    # 1. Suspicious Keywords
    # --------------------------------
    keyword_count = features.get("keyword_count", 0)

    if keyword_count > 0:

        keyword_score = min(keyword_count * 10, 30)
        score += keyword_score

        for keyword in features.get("matched_keywords", []):
            reasons.append(
                f"Suspicious keyword: {keyword}"
            )

    # --------------------------------
    # 2. HTTPS Check
    # --------------------------------
    if not features.get("is_https", False):

        score += 15

        reasons.append(
            "URL does not use HTTPS"
        )

    # --------------------------------
    # 3. Suspicious TLD
    # --------------------------------
    if features.get("suspicious_tld", False):

        score += 20

        reasons.append(
            "Suspicious top-level domain detected"
        )

    # --------------------------------
    # 4. IP Address
    # --------------------------------
    if features.get("is_ip_address", False):

        score += 20

        reasons.append(
            "URL uses an IP address instead of a domain"
        )

    # --------------------------------
    # 5. @ Symbol
    # --------------------------------
    if features.get("has_at_symbol", False):

        score += 15

        reasons.append(
            "URL contains @ symbol"
        )

    # --------------------------------
    # 6. Multiple Hyphens
    # --------------------------------
    hyphen_count = features.get(
        "hyphen_count",
        0
    )

    if hyphen_count >= 3:

        score += 10

        reasons.append(
            "URL contains multiple hyphens"
        )

    # --------------------------------
    # 7. Multiple Subdomains
    # --------------------------------
    subdomain_count = features.get(
        "subdomain_count",
        0
    )

    if subdomain_count >= 2:

        score += 10

        reasons.append(
            "URL contains multiple subdomains"
        )

    # --------------------------------
    # 8. URL Shortener
    # --------------------------------
    if features.get(
        "is_shortened_url",
        False
    ):

        score += 30

        reasons.append(
            "URL uses a URL shortening service"
        )

    # --------------------------------
    # 9. Very Long URL
    # --------------------------------
    url_length = features.get(
        "url_length",
        0
    )

    if url_length > 100:

        score += 10

        reasons.append(
            "URL is unusually long"
        )

    # --------------------------------
    # 10. Keep Score Between 0-100
    # --------------------------------
    score = min(score, 100)

    # --------------------------------
    # 11. Final Verdict
    # --------------------------------
    if score >= 60:

        verdict = "SCAM"

    elif score >= 30:

        verdict = "SUSPICIOUS"

    else:

        verdict = "SAFE"

    # --------------------------------
    # 12. Final Result
    # --------------------------------
    return {
        "risk_score": score,
        "verdict": verdict,
        "reasons": reasons
    }