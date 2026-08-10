import sys
from pathlib import Path

import pandas as pd

# ------------------------------------------------------------
# Add backend directory to Python path
# ------------------------------------------------------------

BACKEND_DIR = Path(__file__).resolve().parents[2]

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


from app.services.feature_extractor import extract_features


# ------------------------------------------------------------
# Paths
# ------------------------------------------------------------

CURRENT_DIR = Path(__file__).resolve().parent

INPUT_FILE = (
    CURRENT_DIR / "phishing_urls.csv"
)

OUTPUT_FILE = (
    CURRENT_DIR / "sentinel_features.csv"
)


# ------------------------------------------------------------
# Features used by Sentinel ML model
# ------------------------------------------------------------

FEATURE_COLUMNS = [
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


# ------------------------------------------------------------
# Convert extracted features into ML-friendly values
# ------------------------------------------------------------

def build_feature_row(url):
    """
    Extract Sentinel features from one URL
    and convert them into numeric values.
    """

    features = extract_features(url)

    row = {}

    for column in FEATURE_COLUMNS:

        value = features.get(
            column,
            0
        )

        # Convert booleans to integers
        if isinstance(value, bool):
            value = int(value)

        # Make sure numerical values are valid
        try:
            value = int(value)
        except (TypeError, ValueError):
            value = 0

        row[column] = value

    return row


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():

    print("Loading phishing URL dataset...")

    df = pd.read_csv(
        INPUT_FILE
    )

    print(
        f"Loaded {len(df)} URLs."
    )

    if "URL" not in df.columns:
        raise ValueError(
            "URL column not found in dataset."
        )

    if "Label" not in df.columns:
        raise ValueError(
            "Label column not found in dataset."
        )

    # --------------------------------------------------------
    # Prepare rows
    # --------------------------------------------------------

    rows = []

    total = len(df)

    print()
    print(
        "Extracting Sentinel features..."
    )

    for index, url in enumerate(
        df["URL"],
        start=1
    ):

        try:

            row = build_feature_row(
                str(url)
            )

            row["Label"] = int(
                df.iloc[index - 1]["Label"]
            )

            rows.append(row)

        except Exception as error:

            print(
                f"Skipping URL {index}: {error}"
            )

        # Progress every 10,000 URLs
        if index % 10000 == 0:

            print(
                f"Processed {index}/{total} URLs..."
            )

    # --------------------------------------------------------
    # Create final dataframe
    # --------------------------------------------------------

    feature_df = pd.DataFrame(
        rows
    )

    # --------------------------------------------------------
    # Remove invalid rows
    # --------------------------------------------------------

    feature_df = feature_df.dropna()

    # Ensure correct column order
    feature_df = feature_df[
        FEATURE_COLUMNS + ["Label"]
    ]

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    feature_df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print()
    print(
        "========================================"
    )

    print(
        "Sentinel feature preparation complete!"
    )

    print(
        "========================================"
    )

    print(
        f"Total rows: {len(feature_df)}"
    )

    print(
        f"Total features: {len(FEATURE_COLUMNS)}"
    )

    print()
    print(
        "Feature columns:"
    )

    for column in FEATURE_COLUMNS:
        print(
            f"  - {column}"
        )

    print()
    print(
        "Label distribution:"
    )

    print(
        feature_df["Label"].value_counts()
    )

    print()
    print(
        "Saved to:"
    )

    print(
        OUTPUT_FILE
    )


if __name__ == "__main__":
    main()