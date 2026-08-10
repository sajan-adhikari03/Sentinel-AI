import os
import re
import joblib
import numpy as np
import pandas as pd

from scipy.sparse import hstack, csr_matrix

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)


# ============================================================
# CONFIG
# ============================================================

DATASET_PATH = "ml/dataset/phishing_urls.csv"
FEATURE_PATH = "ml/dataset/sentinel_features.csv"
MODEL_PATH = "ml/models/url_ml_model.joblib"

RANDOM_STATE = 42


# ============================================================
# TRUSTED LEGITIMATE URL SEEDS
# ============================================================
# These are used ONLY to teach the model common legitimate
# domain patterns that may be missing from the phishing dataset.
#
# Label:
# 0 = Legitimate
# 1 = Phishing
# ============================================================

TRUSTED_URLS = [
    # Search / Technology
    "https://google.com",
    "https://www.google.com",
    "https://github.com",
    "https://www.github.com",
    "https://microsoft.com",
    "https://www.microsoft.com",
    "https://apple.com",
    "https://www.apple.com",
    "https://amazon.com",
    "https://www.amazon.com",
    "https://wikipedia.org",
    "https://www.wikipedia.org",

    # Social
    "https://facebook.com",
    "https://www.facebook.com",
    "https://instagram.com",
    "https://www.instagram.com",
    "https://linkedin.com",
    "https://www.linkedin.com",
    "https://twitter.com",
    "https://www.twitter.com",
    "https://x.com",
    "https://www.x.com",

    # Development
    "https://stackoverflow.com",
    "https://www.stackoverflow.com",
    "https://npmjs.com",
    "https://www.npmjs.com",
    "https://python.org",
    "https://www.python.org",
    "https://nodejs.org",
    "https://www.nodejs.org",

    # Microsoft services
    "https://office.com",
    "https://www.office.com",
    "https://outlook.com",
    "https://www.outlook.com",
    "https://azure.com",
    "https://www.azure.com",

    # Google services
    "https://youtube.com",
    "https://www.youtube.com",
    "https://gmail.com",
    "https://www.gmail.com",
    "https://drive.google.com",
    "https://docs.google.com",

    # Education / reference
    "https://mit.edu",
    "https://www.mit.edu",
    "https://harvard.edu",
    "https://www.harvard.edu",
    "https://stanford.edu",
    "https://www.stanford.edu",

    # Security / technology
    "https://cloudflare.com",
    "https://www.cloudflare.com",
    "https://cisco.com",
    "https://www.cisco.com",
    "https://ibm.com",
    "https://www.ibm.com",
    "https://intel.com",
    "https://www.intel.com",

    # Major services
    "https://paypal.com",
    "https://www.paypal.com",
    "https://ebay.com",
    "https://www.ebay.com",
    "https://netflix.com",
    "https://www.netflix.com",
    "https://spotify.com",
    "https://www.spotify.com",

    # News / public
    "https://bbc.com",
    "https://www.bbc.com",
    "https://cnn.com",
    "https://www.cnn.com",

    # Indian services
    "https://gov.in",
    "https://www.gov.in",
    "https://nic.in",
    "https://www.nic.in",
    "https://uidai.gov.in",
    "https://www.uidai.gov.in",
    "https://incometax.gov.in",
    "https://www.incometax.gov.in",
]


# ============================================================
# NORMALIZE URL
# ============================================================

def normalize_url(url):
    """
    Normalize URLs before training.

    Important:
    - Removes markdown links
    - Removes surrounding spaces
    - Removes escaped colon
    - Adds https:// when scheme is missing
    """

    if url is None:
        return ""

    url = str(url).strip()

    # --------------------------------------------------------
    # Remove Markdown link format:
    # [https://google.com](https://google.com)
    # --------------------------------------------------------

    markdown_match = re.fullmatch(
        r"\[([^\]]+)\]\(([^)]+)\)",
        url
    )

    if markdown_match:
        url = markdown_match.group(2).strip()

    # --------------------------------------------------------
    # Remove escaped colon
    # https\://google.com
    # --------------------------------------------------------

    url = url.replace("\\:", ":")

    # --------------------------------------------------------
    # Remove surrounding quotes
    # --------------------------------------------------------

    url = url.strip("\"'")

    # --------------------------------------------------------
    # Remove whitespace
    # --------------------------------------------------------

    url = re.sub(r"\s+", "", url)

    # --------------------------------------------------------
    # Add scheme if missing
    # --------------------------------------------------------

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url

    return url.lower()


# ============================================================
# LOAD DATA
# ============================================================

print("=" * 70)
print("SENTINEL URL ML TRAINING")
print("=" * 70)

print("\nLoading URL dataset...")

df_urls = pd.read_csv(DATASET_PATH)

print("Loading Sentinel features...")

df_features = pd.read_csv(FEATURE_PATH)

print(f"URLs: {len(df_urls)}")
print(f"Features: {len(df_features)}")


# ============================================================
# DATASET VALIDATION
# ============================================================

if len(df_urls) != len(df_features):
    raise ValueError(
        f"Dataset mismatch: URLs={len(df_urls)}, "
        f"Features={len(df_features)}"
    )


if "URL" not in df_urls.columns:
    raise ValueError("'URL' column not found.")


if "Label" not in df_urls.columns:
    raise ValueError("'Label' column not found.")


# ============================================================
# CLEAN ORIGINAL DATA
# ============================================================

urls = (
    df_urls["URL"]
    .fillna("")
    .astype(str)
    .map(normalize_url)
)

y = df_urls["Label"].astype(int)

valid = urls.str.len() > 0

urls = urls[valid].reset_index(drop=True)
y = y[valid].reset_index(drop=True)

df_features = (
    df_features.loc[valid]
    .reset_index(drop=True)
)


print(f"\nValid original URLs: {len(urls)}")


# ============================================================
# FEATURE COLUMNS
# ============================================================

feature_columns = [
    "url_length",
    "is_https",
    "dot_count",
    "keyword_count",
    "is_ip_address",
    "has_at_symbol",
    "hyphen_count",
    "subdomain_count",
    "suspicious_tld",
    "is_shortened_url",
    "path_keyword_count",
    "query_parameter_count",
    "has_fragment",
    "has_encoded_characters",
    "uses_punycode",
    "hostname_length",
    "digit_count_in_hostname",
    "digit_heavy_domain",
    "has_repeated_separators",
]


missing = [
    col
    for col in feature_columns
    if col not in df_features.columns
]

if missing:
    raise ValueError(
        f"Missing feature columns: {missing}"
    )


X_numeric_original = (
    df_features[feature_columns]
    .fillna(0)
    .astype(float)
)


# ============================================================
# REMOVE DUPLICATES FROM ORIGINAL DATA
# ============================================================

original_data = pd.DataFrame({
    "url": urls,
    "label": y,
})

original_data = (
    original_data
    .drop_duplicates(subset=["url", "label"])
    .reset_index(drop=True)
)


print(
    f"Unique original URL/label records: "
    f"{len(original_data)}"
)


# ============================================================
# CREATE TRUSTED DATA
# ============================================================

trusted_urls = [
    normalize_url(url)
    for url in TRUSTED_URLS
]

trusted_urls = list(
    dict.fromkeys(trusted_urls)
)


trusted_df = pd.DataFrame({
    "url": trusted_urls,
    "label": 0,
})


# Remove trusted URL if it already exists with any label.
# This prevents contradictory training labels.
original_urls_set = set(original_data["url"])

trusted_df = trusted_df[
    ~trusted_df["url"].isin(original_urls_set)
].reset_index(drop=True)


print(
    f"Trusted legitimate seed URLs added: "
    f"{len(trusted_df)}"
)


# ============================================================
# BUILD FINAL URL DATASET
# ============================================================

final_urls = pd.concat(
    [
        original_data[["url", "label"]],
        trusted_df[["url", "label"]],
    ],
    ignore_index=True,
)


print(
    f"\nFinal training records: "
    f"{len(final_urls)}"
)


print("\nFinal label distribution:")

print(
    final_urls["label"]
    .value_counts()
    .sort_index()
)


print("\nExpected:")
print("0 = Legitimate")
print("1 = Phishing")


# ============================================================
# CREATE NUMERIC FEATURES FOR ORIGINAL DATA
# ============================================================

original_feature_data = pd.DataFrame(
    X_numeric_original
)

original_feature_data["url"] = urls

original_feature_data = (
    original_feature_data
    .drop_duplicates(subset=["url"])
)


# ============================================================
# FEATURE EXTRACTION FOR TRUSTED URL SEEDS
# ============================================================

def basic_url_features(url):

    from urllib.parse import urlparse

    parsed = urlparse(url)

    hostname = parsed.hostname or ""

    path = parsed.path or ""

    query = parsed.query or ""

    return {
        "url_length": len(url),

        "is_https": int(
            parsed.scheme.lower() == "https"
        ),

        "dot_count": url.count("."),

        "keyword_count": 0,

        "is_ip_address": 0,

        "has_at_symbol": int("@" in url),

        "hyphen_count": hostname.count("-"),

        "subdomain_count": max(
            len(hostname.split(".")) - 2,
            0,
        ),

        "suspicious_tld": int(
            hostname.endswith(
                (
                    ".tk",
                    ".ml",
                    ".ga",
                    ".cf",
                    ".gq",
                    ".top",
                    ".xyz",
                )
            )
        ),

        "is_shortened_url": int(
            hostname in {
                "bit.ly",
                "tinyurl.com",
                "t.co",
                "is.gd",
                "tiny.one",
                "rebrand.ly",
            }
        ),

        "path_keyword_count": 0,

        "query_parameter_count": (
            query.count("&") + 1
            if query
            else 0
        ),

        "has_fragment": int(
            bool(parsed.fragment)
        ),

        "has_encoded_characters": int(
            "%" in url
        ),

        "uses_punycode": int(
            "xn--" in hostname.lower()
        ),

        "hostname_length": len(hostname),

        "digit_count_in_hostname": sum(
            c.isdigit()
            for c in hostname
        ),

        "digit_heavy_domain": int(
            sum(c.isdigit() for c in hostname)
            > max(len(hostname) * 0.3, 3)
        ),

        "has_repeated_separators": int(
            ".." in url
            or "//" in parsed.path
            or "--" in hostname
        ),
    }


trusted_feature_data = pd.DataFrame(
    [
        basic_url_features(url)
        for url in trusted_df["url"]
    ]
)


# ============================================================
# COMBINE NUMERIC FEATURES
# ============================================================

original_numeric = original_feature_data[
    feature_columns
].copy()

trusted_numeric = trusted_feature_data[
    feature_columns
].copy()


X_numeric = pd.concat(
    [
        original_numeric,
        trusted_numeric,
    ],
    ignore_index=True,
)


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

print("\nSplitting dataset...")

urls_all = final_urls["url"].reset_index(drop=True)

y_all = final_urls["label"].reset_index(drop=True)


(
    urls_train,
    urls_test,
    X_num_train,
    X_num_test,
    y_train,
    y_test,
) = train_test_split(
    urls_all,
    X_numeric,
    y_all,
    test_size=0.20,
    random_state=RANDOM_STATE,
    stratify=y_all,
)


print(
    f"Training samples: {len(y_train)}"
)

print(
    f"Testing samples: {len(y_test)}"
)


# ============================================================
# CHARACTER TF-IDF
# ============================================================

print(
    "\nCreating character-level URL representation..."
)


vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(3, 5),
    min_df=2,
    max_features=120000,
    sublinear_tf=True,
    lowercase=True,
)


X_text_train = vectorizer.fit_transform(
    urls_train
)


X_text_test = vectorizer.transform(
    urls_test
)


print(
    f"Character features: "
    f"{X_text_train.shape[1]}"
)


# ============================================================
# COMBINE FEATURES
# ============================================================

print(
    "\nCombining URL patterns with Sentinel features..."
)


X_train = hstack(
    [
        X_text_train,
        csr_matrix(X_num_train.values),
    ]
).tocsr()


X_test = hstack(
    [
        X_text_test,
        csr_matrix(X_num_test.values),
    ]
).tocsr()


print(
    f"Final training matrix: "
    f"{X_train.shape}"
)


# ============================================================
# BASE MODEL
# ============================================================

print("\nTraining Logistic Regression model...")


base_model = LogisticRegression(
    C=2.0,
    max_iter=2000,
    solver="liblinear",
    random_state=RANDOM_STATE,
)


base_model.fit(
    X_train,
    y_train,
)


print("Base model training complete.")


# ============================================================
# CALIBRATION
# ============================================================

print(
    "\nCalibrating ML probabilities..."
)


calibrated_model = CalibratedClassifierCV(
    estimator=base_model,
    method="sigmoid",
    cv=3,
)


calibrated_model.fit(
    X_train,
    y_train,
)


print(
    "Probability calibration complete."
)


# ============================================================
# EVALUATION
# ============================================================

print("\nEvaluating model...")


predictions = calibrated_model.predict(
    X_test
)


probabilities = (
    calibrated_model.predict_proba(X_test)[:, 1]
)


accuracy = accuracy_score(
    y_test,
    predictions,
)


precision = precision_score(
    y_test,
    predictions,
    zero_division=0,
)


recall = recall_score(
    y_test,
    predictions,
    zero_division=0,
)


f1 = f1_score(
    y_test,
    predictions,
    zero_division=0,
)


auc = roc_auc_score(
    y_test,
    probabilities,
)


print()

print(
    f"Accuracy : {accuracy:.4f}"
)

print(
    f"Precision: {precision:.4f}"
)

print(
    f"Recall   : {recall:.4f}"
)

print(
    f"F1 Score : {f1:.4f}"
)

print(
    f"ROC AUC  : {auc:.4f}"
)


# ============================================================
# CLASSIFICATION REPORT
# ============================================================

print(
    "\nClassification Report:"
)


print(
    classification_report(
        y_test,
        predictions,
        target_names=[
            "Legitimate",
            "Phishing",
        ],
        zero_division=0,
    )
)


# ============================================================
# CONFUSION MATRIX
# ============================================================

print(
    "Confusion Matrix:"
)


print(
    confusion_matrix(
        y_test,
        predictions,
    )
)


# ============================================================
# TEST KNOWN TRUSTED DOMAINS
# ============================================================

print(
    "\nTesting trusted domains..."
)


trusted_test_urls = [
    "https://google.com",
    "https://github.com",
    "https://microsoft.com",
    "https://wikipedia.org",
    "https://apple.com",
    "https://amazon.com",
    "https://youtube.com",
]


trusted_test_matrix = vectorizer.transform(
    trusted_test_urls
)


trusted_test_numeric = pd.DataFrame(
    [
        basic_url_features(url)
        for url in trusted_test_urls
    ]
)[feature_columns]


trusted_test_X = hstack(
    [
        trusted_test_matrix,
        csr_matrix(
            trusted_test_numeric.values
        ),
    ]
).tocsr()


trusted_predictions = (
    calibrated_model.predict(
        trusted_test_X
    )
)


trusted_probabilities = (
    calibrated_model.predict_proba(
        trusted_test_X
    )[:, 1]
)


for url, pred, prob in zip(
    trusted_test_urls,
    trusted_predictions,
    trusted_probabilities,
):

    verdict = (
        "PHISHING"
        if pred == 1
        else "LEGITIMATE"
    )

    print(
        f"{url:<35} "
        f"=> {verdict:<10} "
        f"Phishing={prob * 100:.2f}%"
    )


# ============================================================
# SAVE MODEL
# ============================================================

os.makedirs(
    os.path.dirname(MODEL_PATH),
    exist_ok=True,
)


joblib.dump(
    {
        "model": calibrated_model,
        "vectorizer": vectorizer,
        "features": feature_columns,
        "version": "sentinel-url-calibrated-v2",
        "trusted_domains": TRUSTED_URLS,
    },
    MODEL_PATH,
)


print(
    "\n============================================================"
)

print(
    "MODEL SAVED SUCCESSFULLY"
)

print(
    "============================================================"
)

print(
    os.path.abspath(MODEL_PATH)
)