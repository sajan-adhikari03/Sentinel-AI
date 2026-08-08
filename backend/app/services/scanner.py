from app.services.feature_extractor import extract_features
from app.services.risk_engine import calculate_risk


def scan_url(url):
    """
    Complete URL scanning pipeline.

    URL
      ↓
    Feature Extraction
      ↓
    Risk Analysis
      ↓
    Final Result
    """

    # Basic input validation
    if not url or not isinstance(url, str):
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

    # Step 1: Extract URL features
    features = extract_features(url)

    # Step 2: Calculate risk
    risk_result = calculate_risk(features)

    # Step 3: Combine everything
    return {
        "success": True,
        "url": url,
        "risk_score": risk_result["risk_score"],
        "verdict": risk_result["verdict"],
        "reasons": risk_result["reasons"],
        "features": features
    }