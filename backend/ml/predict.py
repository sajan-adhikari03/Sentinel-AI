import os
import re
import joblib
import numpy as np

from scipy.sparse import hstack, csr_matrix

from app.services.feature_extractor import extract_features
from ml.trusted_domains import is_trusted_domain


# ============================================================
# CONFIGURATION
# ============================================================

MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "models",
    "url_ml_model.joblib"
)

_model_data = None


# ============================================================
# TRUSTED BRANDS
# ============================================================

TRUSTED_BRANDS = {
    "google.com": "Google",
    "github.com": "GitHub",
    "microsoft.com": "Microsoft",
    "apple.com": "Apple",
    "amazon.com": "Amazon",
    "wikipedia.org": "Wikipedia",
    "youtube.com": "YouTube",
    "facebook.com": "Facebook",
    "instagram.com": "Instagram",
    "linkedin.com": "LinkedIn",
    "twitter.com": "Twitter",
    "x.com": "X",
    "paypal.com": "PayPal",
    "netflix.com": "Netflix",
    "spotify.com": "Spotify",
    "adobe.com": "Adobe",
    "cloudflare.com": "Cloudflare",
    "cisco.com": "Cisco",
    "ibm.com": "IBM",
    "intel.com": "Intel",
    "stackoverflow.com": "Stack Overflow",
    "python.org": "Python",
    "npmjs.com": "npm",
    "nodejs.org": "Node.js",
    "mozilla.org": "Mozilla",
    "outlook.com": "Outlook",
    "office.com": "Microsoft Office",
    "azure.com": "Microsoft Azure",
}


# ============================================================
# URL NORMALIZATION
# ============================================================

def normalize_url(url):
    """
    Convert different URL formats into a clean raw URL.
    """

    if not isinstance(url, str):
        return ""

    url = url.strip()

    # Markdown:
    # [https://google.com](https://google.com)
    markdown_match = re.search(
        r"\]\(\s*(https?://[^)\s]+)\s*\)",
        url,
        re.IGNORECASE
    )

    if markdown_match:
        url = markdown_match.group(1)

    else:

        # [https://google.com]
        bracket_match = re.search(
            r"\[\s*(https?://[^\]\s]+)\s*\]",
            url,
            re.IGNORECASE
        )

        if bracket_match:
            url = bracket_match.group(1)

    # Fix escaped colon
    url = url.replace("\\:", ":")

    # Remove angle brackets
    if url.startswith("<") and url.endswith(">"):
        url = url[1:-1].strip()

    # Remove quotes
    url = url.strip("\"'")

    # Remove newlines
    url = (
        url
        .replace("\n", "")
        .replace("\r", "")
        .strip()
    )

    return url


# ============================================================
# BRAND IMPERSONATION
# ============================================================

def detect_brand_impersonation(hostname):
    """
    Detect obvious trusted-brand impersonation.

    SAFE examples:

        google.com
        www.google.com
        mail.google.com

    DETECT examples:

        google.com.evil.com
        google-login.evil.com
        microsoft-security.evil.com

    Important:
        Single-character brands such as X are NOT matched
        against arbitrary characters.
    """

    if not hostname:
        return None

    hostname = hostname.lower().strip(".")

    labels = [
        label
        for label in hostname.split(".")
        if label
    ]

    # --------------------------------------------------------
    # Check each trusted brand
    # --------------------------------------------------------

    for domain, brand in TRUSTED_BRANDS.items():

        domain = domain.lower()

        domain_parts = domain.split(".")

        # ----------------------------------------------------
        # Official domain
        # ----------------------------------------------------

        if hostname == domain:
            continue

        # ----------------------------------------------------
        # Official subdomain
        # ----------------------------------------------------

        if hostname.endswith("." + domain):
            continue

        # ----------------------------------------------------
        # Exact trusted domain appearing as hostname suffix
        #
        # google.com.evil.com
        #
        # This is NOT an official Google domain because
        # google.com is not the hostname suffix.
        # ----------------------------------------------------

        if domain in hostname:

            # Make sure it appears as complete labels,
            # not merely as random characters.
            for i in range(
                len(labels) - len(domain_parts) + 1
            ):

                candidate = ".".join(
                    labels[
                        i:i + len(domain_parts)
                    ]
                )

                if candidate == domain:

                    return brand

        # ----------------------------------------------------
        # Brand-token detection
        # ----------------------------------------------------

        # Never perform single-character substring matching.
        #
        # Otherwise:
        #
        # example.com
        #       ^
        #       X
        #
        # would incorrectly become X impersonation.
        # ----------------------------------------------------

        brand_token = (
            brand
            .lower()
            .replace(" ", "")
            .replace("-", "")
            .replace(".", "")
        )

        if len(brand_token) <= 1:
            continue

        # Check hostname labels.
        for label in labels:

            normalized_label = re.sub(
                r"[^a-z0-9]",
                "",
                label.lower()
            )

            if not normalized_label:
                continue

            # Exact brand label:
            #
            # google-login
            # microsoft-security
            #
            if (
                normalized_label == brand_token
                or normalized_label.startswith(
                    brand_token
                )
                or normalized_label.endswith(
                    brand_token
                )
            ):

                return brand

            # Brand separated by common delimiters.
            parts = re.split(
                r"[-_]+",
                label.lower()
            )

            for part in parts:

                if part == brand_token:
                    return brand

    return None


# ============================================================
# LOAD MODEL
# ============================================================

def load_model():

    global _model_data

    if _model_data is None:

        if not os.path.exists(MODEL_PATH):

            raise FileNotFoundError(
                "ML model not found:\n"
                f"{MODEL_PATH}\n\n"
                "Run:\n"
                "python ml\\train.py"
            )

        print(
            "Loading Sentinel URL ML model..."
        )

        _model_data = joblib.load(
            MODEL_PATH
        )

        print(
            "ML model loaded successfully."
        )

    return _model_data


# ============================================================
# BUILD NUMERIC FEATURE VECTOR
# ============================================================

def build_numeric_vector(
    features,
    feature_columns
):

    values = []

    for column in feature_columns:

        value = features.get(
            column,
            0
        )

        if isinstance(value, bool):
            value = int(value)

        try:
            value = float(value)
        except (
            TypeError,
            ValueError
        ):
            value = 0.0

        values.append(value)

    array = np.array(
        values,
        dtype=float
    ).reshape(
        1,
        -1
    )

    return csr_matrix(
        array
    )


# ============================================================
# RUN ML MODEL
# ============================================================

def run_ml_prediction(
    clean_url,
    features
):

    model_data = load_model()

    model = model_data["model"]

    vectorizer = model_data["vectorizer"]

    feature_columns = model_data["features"]

    # Character TF-IDF
    text_vector = vectorizer.transform(
        [clean_url]
    )

    # Sentinel numeric features
    numeric_vector = build_numeric_vector(
        features,
        feature_columns
    )

    # Combine
    X = hstack(
        [
            text_vector,
            numeric_vector
        ]
    ).tocsr()

    # Prediction
    prediction = int(
        model.predict(X)[0]
    )

    # Probability
    probabilities = model.predict_proba(
        X
    )[0]

    legitimate_probability = (
        float(probabilities[0]) * 100
    )

    phishing_probability = (
        float(probabilities[1]) * 100
    )

    verdict = (
        "PHISHING"
        if prediction == 1
        else "LEGITIMATE"
    )

    return {
        "prediction": prediction,
        "verdict": verdict,
        "legitimate_probability": round(
            legitimate_probability,
            2
        ),
        "phishing_probability": round(
            phishing_probability,
            2
        )
    }


# ============================================================
# MAIN PREDICTION FUNCTION
# ============================================================

def predict_url(url):
    """
    Complete Sentinel URL detection pipeline.

    1. Normalize URL
    2. Extract features
    3. Check trusted domain
    4. Check brand impersonation
    5. Run ML for remaining URLs
    """

    # --------------------------------------------------------
    # 1. Normalize
    # --------------------------------------------------------

    clean_url = normalize_url(url)

    if not clean_url:
        raise ValueError(
            "A valid URL is required."
        )

    # --------------------------------------------------------
    # 2. Validate scheme
    # --------------------------------------------------------

    if not clean_url.lower().startswith(
        ("http://", "https://")
    ):

        raise ValueError(
            "URL must start with http:// or https://"
        )

    # --------------------------------------------------------
    # 3. Extract Sentinel features
    # --------------------------------------------------------

    features = extract_features(
        clean_url
    )

    hostname = features.get(
        "hostname",
        ""
    )

    hostname = (
        hostname
        .lower()
        .strip(".")
    )

    # --------------------------------------------------------
    # 4. Trusted domain
    # --------------------------------------------------------

    trusted_domain = is_trusted_domain(
        hostname
    )

    if trusted_domain:

        return {
            "url": clean_url,
            "prediction": 0,
            "verdict": "LEGITIMATE",
            "legitimate_probability": 99.99,
            "phishing_probability": 0.01,
            "trusted_domain": True,
            "brand_impersonation": None,
            "detection_source": "TRUSTED_DOMAIN",
            "features": features,
        }

    # --------------------------------------------------------
    # 5. Brand impersonation
    # --------------------------------------------------------

    brand_impersonation = (
        detect_brand_impersonation(
            hostname
        )
    )

    if brand_impersonation:

        return {
            "url": clean_url,
            "prediction": 1,
            "verdict": "PHISHING",
            "legitimate_probability": 0.01,
            "phishing_probability": 99.99,
            "trusted_domain": False,
            "brand_impersonation": brand_impersonation,
            "detection_source": "BRAND_IMPERSONATION",
            "features": features,
        }

    # --------------------------------------------------------
    # 6. ML prediction
    # --------------------------------------------------------

    ml_result = run_ml_prediction(
        clean_url,
        features
    )

    # --------------------------------------------------------
    # 7. Final ML result
    # --------------------------------------------------------

    return {
        "url": clean_url,
        "prediction": ml_result["prediction"],
        "verdict": ml_result["verdict"],
        "legitimate_probability": (
            ml_result["legitimate_probability"]
        ),
        "phishing_probability": (
            ml_result["phishing_probability"]
        ),
        "trusted_domain": False,
        "brand_impersonation": None,
        "detection_source": "ML_MODEL",
        "features": features,
    }