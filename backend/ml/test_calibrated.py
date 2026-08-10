import sys
from pathlib import Path

import joblib
import pandas as pd


# ============================================================
# ADD BACKEND DIRECTORY TO PYTHON PATH
# ============================================================

BACKEND_DIR = Path(__file__).resolve().parents[1]

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


from app.services.feature_extractor import extract_features


# ============================================================
# MODEL PATH
# ============================================================

MODEL_PATH = (
    BACKEND_DIR
    / "ml"
    / "models"
    / "calibrated_random_forest.joblib"
)


# ============================================================
# LOAD MODEL
# ============================================================

print("Loading calibrated Random Forest...")

if not MODEL_PATH.exists():
    raise FileNotFoundError(
        f"Calibrated model not found:\n{MODEL_PATH}"
    )

model_data = joblib.load(
    MODEL_PATH
)

model = model_data["model"]

feature_columns = model_data["features"]

print("Model loaded successfully.")


# ============================================================
# PREDICTION FUNCTION
# ============================================================

def test_url(url):

    print()
    print("========================================")
    print("TEST URL")
    print("========================================")

    print(
        "URL:",
        repr(url)
    )

    # --------------------------------------------------------
    # Extract features
    # --------------------------------------------------------

    features = extract_features(url)

    # --------------------------------------------------------
    # Build ML feature row
    # --------------------------------------------------------

    row = {}

    for feature in feature_columns:

        value = features.get(
            feature,
            0
        )

        if isinstance(value, bool):
            value = int(value)

        try:
            value = int(value)

        except (
            TypeError,
            ValueError
        ):
            value = 0

        row[feature] = value

    X = pd.DataFrame(
        [row],
        columns=feature_columns
    )

    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    prediction = model.predict(
        X
    )[0]

    probabilities = model.predict_proba(
        X
    )[0]

    class_probabilities = dict(
        zip(
            model.classes_,
            probabilities
        )
    )

    legitimate_probability = (
        class_probabilities.get(
            0,
            0
        ) * 100
    )

    phishing_probability = (
        class_probabilities.get(
            1,
            0
        ) * 100
    )

    # --------------------------------------------------------
    # Verdict
    # --------------------------------------------------------

    if prediction == 1:
        verdict = "PHISHING"
    else:
        verdict = "LIKELY LEGITIMATE"

    # --------------------------------------------------------
    # Print result
    # --------------------------------------------------------

    print()
    print("Prediction:", prediction)

    print(
        "Verdict:",
        verdict
    )

    print(
        f"Legitimate probability: "
        f"{legitimate_probability:.2f}%"
    )

    print(
        f"Phishing probability: "
        f"{phishing_probability:.2f}%"
    )

    # --------------------------------------------------------
    # Important features
    # --------------------------------------------------------

    print()
    print("Important Features:")

    important_features = [
        "url_length",
        "is_https",
        "keyword_count",
        "is_ip_address",
        "has_at_symbol",
        "hyphen_count",
        "subdomain_count",
        "suspicious_tld",
        "is_shortened_url",
        "path_keyword_count",
        "query_parameter_count",
        "hostname_length",
        "digit_count_in_hostname",
        "digit_heavy_domain",
        "uses_punycode"
    ]

    for feature in important_features:

        if feature in features:

            print(
                f"{feature}: "
                f"{features[feature]}"
            )

    return {
        "url": url,
        "prediction": int(prediction),
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
# TEST URLs
# ============================================================

test_urls = [

    # Known legitimate website
    "https://google.com",

    # Suspicious phishing-style URL
    "http://example.com/login?verify=account",

    # Previously tested suspicious website
    "https://www.tashanok.cc/#/register?invitationCode=641236123329",

    # Unseen simple domain
    "https://test-example.com"
]


# ============================================================
# RUN TESTS
# ============================================================

print()
print("========================================")
print("SENTINEL CALIBRATED MODEL TEST")
print("========================================")

results = []

for url in test_urls:

    result = test_url(url)

    results.append(
        result
    )


# ============================================================
# SUMMARY
# ============================================================

print()
print()
print("========================================")
print("FINAL SUMMARY")
print("========================================")

for result in results:

    print()
    print(
        "URL:",
        result["url"]
    )

    print(
        "Verdict:",
        result["verdict"]
    )

    print(
        "Legitimate:",
        f"{result['legitimate_probability']:.2f}%"
    )

    print(
        "Phishing:",
        f"{result['phishing_probability']:.2f}%"
    )


print()
print("========================================")
print("TEST COMPLETE")
print("========================================")