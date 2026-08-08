from urllib.parse import urlparse
from app.data.suspicious_keywords import SUSPICIOUS_KEYWORDS


def extract_features(url):
    """
    Extract basic features from a URL.
    """

    parsed_url = urlparse(url)

    url_lower = url.lower()

    matched_keywords = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in url_lower
    ]

    features = {
        "url_length": len(url),
        "is_https": parsed_url.scheme == "https",
        "dot_count": url.count("."),
        "keyword_count": len(matched_keywords),
        "matched_keywords": matched_keywords
    }

    return features