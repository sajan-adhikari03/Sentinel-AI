from app.services.feature_extractor import extract_features
from app.services.risk_engine import calculate_risk
from ml.predict import predict_url


# ============================================================
# SENTINEL URL SCANNER
# ============================================================

def scan_url(url):
    """
    Complete Sentinel URL scanning pipeline.

    URL
      ↓
    Input Validation
      ↓
    Feature Extraction
      ↓
    Rule Engine
      ↓
    ML Prediction
      ↓
    Trusted Domain / Brand Detection
      ↓
    Hybrid Risk Analysis
      ↓
    Final Result
    """

    # ========================================================
    # 1. INPUT VALIDATION
    # ========================================================

    if not isinstance(url, str):
        return {
            "success": False,
            "error": "A valid URL is required."
        }

    url = url.strip()

    if not url:
        return {
            "success": False,
            "error": "URL cannot be empty."
        }

    # Prevent extremely large input.
    if len(url) > 2048:
        return {
            "success": False,
            "error": "URL is too long. Maximum length is 2048 characters."
        }

    # ========================================================
    # 2. FEATURE EXTRACTION
    # ========================================================

    try:
        features = extract_features(url)

    except Exception as e:
        return {
            "success": False,
            "error": f"Feature extraction failed: {str(e)}"
        }

    # ========================================================
    # 3. RULE ENGINE
    # ========================================================

    try:
        rule_result = calculate_risk(features)

    except Exception as e:
        return {
            "success": False,
            "error": f"Risk analysis failed: {str(e)}"
        }

    rule_score = int(
        rule_result.get(
            "risk_score",
            0
        )
    )

    rule_score = min(
        max(rule_score, 0),
        100
    )

    rule_verdict = rule_result.get(
        "verdict",
        "SAFE"
    )

    reasons = list(
        rule_result.get(
            "reasons",
            []
        )
    )

    # ========================================================
    # 4. ML PREDICTION
    # ========================================================

    try:
        # IMPORTANT:
        # predict_url() receives the original URL.
        ml_result = predict_url(url)

    except Exception as e:
        return {
            "success": False,
            "error": f"ML prediction failed: {str(e)}"
        }

    ml_prediction = int(
        ml_result.get(
            "prediction",
            0
        )
    )

    ml_probability = float(
        ml_result.get(
            "phishing_probability",
            0
        )
    )

    ml_probability = min(
        max(ml_probability, 0.0),
        100.0
    )

    ml_verdict = ml_result.get(
        "verdict",
        "LEGITIMATE"
    )

    trusted_domain = bool(
        ml_result.get(
            "trusted_domain",
            False
        )
    )

    brand_impersonation = ml_result.get(
        "brand_impersonation"
    )

    detection_source = ml_result.get(
        "detection_source",
        "ML_MODEL"
    )

    # ========================================================
    # 5. STRONG SECURITY INDICATORS
    # ========================================================

    strong_indicators = 0

    if features.get(
        "is_ip_address",
        False
    ):
        strong_indicators += 1

    if features.get(
        "has_at_symbol",
        False
    ):
        strong_indicators += 1

    if features.get(
        "suspicious_tld",
        False
    ):
        strong_indicators += 1

    if features.get(
        "is_shortened_url",
        False
    ):
        strong_indicators += 1

    if features.get(
        "has_suspicious_path",
        False
    ):
        strong_indicators += 1

    if features.get(
        "has_suspicious_query",
        False
    ):
        strong_indicators += 1

    if features.get(
        "digit_heavy_domain",
        False
    ):
        strong_indicators += 1

    if features.get(
        "uses_punycode",
        False
    ):
        strong_indicators += 1

    if features.get(
        "has_encoded_characters",
        False
    ):
        strong_indicators += 1

    if features.get(
        "has_repeated_separators",
        False
    ):
        strong_indicators += 1

    # ========================================================
    # 6. COUNT SUSPICIOUS BEHAVIOUR
    # ========================================================

    suspicious_behaviour = 0

    if features.get(
        "keyword_count",
        0
    ) > 0:
        suspicious_behaviour += 1

    if features.get(
        "path_keyword_count",
        0
    ) > 0:
        suspicious_behaviour += 1

    if features.get(
        "query_parameter_count",
        0
    ) > 0:
        suspicious_behaviour += 1

    if features.get(
        "has_suspicious_path",
        False
    ):
        suspicious_behaviour += 1

    if features.get(
        "has_suspicious_query",
        False
    ):
        suspicious_behaviour += 1

    if not features.get(
        "is_https",
        True
    ):
        suspicious_behaviour += 1

    # ========================================================
    # 7. BRAND IMPERSONATION
    # ========================================================

    # Brand impersonation is treated as a very strong signal.
    #
    # Example:
    # google.com.evil.com
    # google-login.evil.com
    #
    # These should remain CRITICAL even if generic rules
    # produce a low score.

    if brand_impersonation:

        final_score = 100

        final_verdict = "CRITICAL"

        final_reasons = list(
            reasons
        )

        impersonation_reason = (
            f"Possible {brand_impersonation} "
            "brand impersonation detected"
        )

        if impersonation_reason not in final_reasons:
            final_reasons.append(
                impersonation_reason
            )

        hostname_reason = (
            "The hostname is not the official "
            "trusted domain"
        )

        if hostname_reason not in final_reasons:
            final_reasons.append(
                hostname_reason
            )

        intelligence_reason = (
            "Machine learning and security intelligence "
            "identify phishing characteristics"
        )

        if intelligence_reason not in final_reasons:
            final_reasons.append(
                intelligence_reason
            )

        return {
            "success": True,

            "url": ml_result.get(
                "url",
                url
            ),

            "risk_score": final_score,

            "verdict": final_verdict,

            "reasons": final_reasons,

            "features": features,

            "ml_prediction": ml_prediction,

            "ml_probability": round(
                ml_probability,
                2
            ),

            "ml_verdict": ml_verdict,

            "trusted_domain": False,

            "brand_impersonation": (
                brand_impersonation
            ),

            "detection_source": (
                "BRAND_IMPERSONATION"
            ),

            "rule_score": rule_score,

            "rule_verdict": rule_verdict
        }

    # ========================================================
    # 8. TRUSTED DOMAIN
    # ========================================================

    # IMPORTANT:
    #
    # Trusted domain is NOT an automatic SAFE override.
    #
    # Example:
    #
    # https://google.com
    #       → SAFE
    #
    # But:
    #
    # https://google.com/login?verify=account
    #       → suspicious indicators still matter.
    #
    # Official domain is a positive security signal,
    # not absolute immunity.

    if trusted_domain:

        # ----------------------------------------------------
        # CLEAN OFFICIAL DOMAIN
        # ----------------------------------------------------

        if (
            rule_score < 30
            and strong_indicators == 0
            and suspicious_behaviour == 0
            and ml_prediction == 0
        ):

            final_score = 0

            final_verdict = "SAFE"

            final_reasons = [
                "Official trusted domain detected",
                "No significant suspicious URL indicators detected"
            ]

            return {
                "success": True,

                "url": ml_result.get(
                    "url",
                    url
                ),

                "risk_score": final_score,

                "verdict": final_verdict,

                "reasons": final_reasons,

                "features": features,

                "ml_prediction": ml_prediction,

                "ml_probability": round(
                    ml_probability,
                    2
                ),

                "ml_verdict": ml_verdict,

                "trusted_domain": True,

                "brand_impersonation": None,

                "detection_source": (
                    "TRUSTED_DOMAIN"
                ),

                "rule_score": rule_score,

                "rule_verdict": rule_verdict
            }

        # ----------------------------------------------------
        # TRUSTED DOMAIN BUT SUSPICIOUS PATH / QUERY
        # ----------------------------------------------------

        if (
            rule_score >= 60
            or strong_indicators >= 2
        ):

            final_score = max(
                rule_score,
                60
            )

            if ml_prediction == 1:
                final_score = max(
                    final_score,
                    min(
                        int(
                            rule_score
                            + ml_probability * 0.15
                        ),
                        85
                    )
                )

            final_reasons = list(
                reasons
            )

            final_reasons.append(
                "Official trusted domain detected, "
                "but suspicious URL behaviour was also found"
            )

            if ml_prediction == 1:
                final_reasons.append(
                    "Machine learning model also "
                    "identified phishing characteristics"
                )

        elif (
            rule_score >= 30
            or strong_indicators >= 1
            or suspicious_behaviour >= 2
        ):

            final_score = max(
                rule_score,
                30
            )

            if ml_prediction == 1:
                final_score = min(
                    max(
                        final_score,
                        int(
                            rule_score
                            + ml_probability * 0.10
                        )
                    ),
                    70
                )

            final_reasons = list(
                reasons
            )

            final_reasons.append(
                "Official trusted domain detected, "
                "but some suspicious URL indicators were found"
            )

        else:

            # Trusted domain with only ML disagreement.
            final_score = min(
                rule_score,
                25
            )

            final_reasons = list(
                reasons
            )

            if ml_prediction == 1:

                final_reasons.append(
                    "Machine learning prediction disagrees "
                    "with the trusted-domain and rule analysis"
                )

        # ----------------------------------------------------
        # FINAL TRUSTED-DOMAIN VERDICT
        # ----------------------------------------------------

        if final_score >= 80:

            final_verdict = "CRITICAL"

        elif final_score >= 60:

            final_verdict = "HIGH RISK"

        elif final_score >= 30:

            final_verdict = "SUSPICIOUS"

        else:

            final_verdict = "SAFE"

        return {
            "success": True,

            "url": ml_result.get(
                "url",
                url
            ),

            "risk_score": min(
                max(
                    int(final_score),
                    0
                ),
                100
            ),

            "verdict": final_verdict,

            "reasons": final_reasons,

            "features": features,

            "ml_prediction": ml_prediction,

            "ml_probability": round(
                ml_probability,
                2
            ),

            "ml_verdict": ml_verdict,

            "trusted_domain": True,

            "brand_impersonation": None,

            "detection_source": (
                "TRUSTED_DOMAIN"
                if final_verdict == "SAFE"
                else "HYBRID_ANALYSIS"
            ),

            "rule_score": rule_score,

            "rule_verdict": rule_verdict
        }

    # ========================================================
    # 9. UNKNOWN / UNTRUSTED DOMAIN
    # ========================================================

    final_score = rule_score

    final_reasons = list(
        reasons
    )

    # ========================================================
    # ML PHISHING CONTRIBUTION
    # ========================================================

    if ml_prediction == 1:

        # ----------------------------------------------------
        # CASE A:
        # Strong rule evidence
        # ----------------------------------------------------

        if rule_score >= 30:

            ml_bonus = min(
                round(
                    ml_probability * 0.20
                ),
                20
            )

            final_score += ml_bonus

            final_reasons.append(
                "Machine learning model also "
                "identified phishing characteristics"
            )

        # ----------------------------------------------------
        # CASE B:
        # Multiple strong indicators
        # ----------------------------------------------------

        elif strong_indicators >= 2:

            ml_bonus = min(
                round(
                    ml_probability * 0.15
                ),
                15
            )

            final_score += ml_bonus

            final_reasons.append(
                "Machine learning model detected "
                "additional phishing indicators"
            )

        # ----------------------------------------------------
        # CASE C:
        # ML alone disagrees
        # ----------------------------------------------------

        else:

            final_reasons.append(
                "Machine learning prediction disagrees "
                "with rule-based URL analysis"
            )

    # ========================================================
    # 10. RULE STRONG BUT ML LEGITIMATE
    # ========================================================

    elif (
        ml_prediction == 0
        and rule_score >= 60
    ):

        final_reasons.append(
            "Rule-based analysis detected strong "
            "suspicious URL indicators"
        )

        final_reasons.append(
            "Machine learning model did not classify "
            "the URL as phishing"
        )

    # ========================================================
    # 11. ADDITIONAL HIGH-CONFIDENCE SIGNAL
    # ========================================================

    # Multiple independent suspicious indicators
    # should never result in a SAFE score.

    if (
        strong_indicators >= 3
        and final_score < 60
    ):

        final_score = max(
            final_score,
            60
        )

        final_reasons.append(
            "Multiple independent high-risk URL "
            "indicators were detected together"
        )

    # ========================================================
    # 12. LIMIT SCORE
    # ========================================================

    final_score = min(
        max(
            int(final_score),
            0
        ),
        100
    )

    # ========================================================
    # 13. FINAL VERDICT
    # ========================================================

    if final_score >= 80:

        final_verdict = "CRITICAL"

    elif final_score >= 60:

        final_verdict = "HIGH RISK"

    elif final_score >= 30:

        final_verdict = "SUSPICIOUS"

    else:

        final_verdict = "SAFE"

    # ========================================================
    # 14. SAFE MESSAGE
    # ========================================================

    if final_verdict == "SAFE":

        if not final_reasons:

            final_reasons = [
                "No significant suspicious URL "
                "indicators detected"
            ]

    # ========================================================
    # 15. DETECTION SOURCE
    # ========================================================

    if final_verdict == "SAFE":

        if trusted_domain:

            final_detection_source = (
                "TRUSTED_DOMAIN"
            )

        else:

            final_detection_source = (
                "ML_MODEL"
                if ml_prediction == 0
                else "RULE_ENGINE"
            )

    else:

        if ml_prediction == 1 and rule_score > 0:

            final_detection_source = (
                "HYBRID_ANALYSIS"
            )

        elif ml_prediction == 1:

            final_detection_source = (
                "ML_MODEL"
            )

        else:

            final_detection_source = (
                "RULE_ENGINE"
            )

    # ========================================================
    # 16. FINAL RESPONSE
    # ========================================================

    return {
        "success": True,

        "url": ml_result.get(
            "url",
            url
        ),

        "risk_score": final_score,

        "verdict": final_verdict,

        "reasons": final_reasons,

        "features": features,

        # -----------------------------
        # ML
        # -----------------------------

        "ml_prediction": ml_prediction,

        "ml_probability": round(
            ml_probability,
            2
        ),

        "ml_verdict": ml_verdict,

        # -----------------------------
        # SECURITY INTELLIGENCE
        # -----------------------------

        "trusted_domain": trusted_domain,

        "brand_impersonation": (
            brand_impersonation
        ),

        "detection_source": (
            final_detection_source
        ),

        # -----------------------------
        # RULE ENGINE
        # -----------------------------

        "rule_score": rule_score,

        "rule_verdict": rule_verdict
    }