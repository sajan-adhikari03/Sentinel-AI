from ucimlrepo import fetch_ucirepo
import pandas as pd
from pathlib import Path


# ============================================================
# Download PhiUSIIL Phishing URL Dataset
# ============================================================

print("Downloading PhiUSIIL dataset...")

dataset = fetch_ucirepo(id=967)

X = dataset.data.features
y = dataset.data.targets


# ============================================================
# Combine URL + Label
# ============================================================

df = X.copy()

# Add target label
df["Label"] = y.iloc[:, 0].values


# ============================================================
# Keep only the columns we need initially
# ============================================================

if "URL" not in df.columns:
    raise ValueError(
        "URL column was not found in the dataset."
    )


df = df[[
    "URL",
    "Label"
]]


# ============================================================
# Convert labels
#
# UCI:
# 1 = Legitimate
# 0 = Phishing
#
# Sentinel:
# 0 = Legitimate
# 1 = Phishing
# ============================================================

df["Label"] = (
    df["Label"]
    .astype(int)
    .map({
        1: 0,
        0: 1
    })
)


# ============================================================
# Remove invalid URLs
# ============================================================

df = df.dropna(
    subset=["URL", "Label"]
)

df["URL"] = (
    df["URL"]
    .astype(str)
    .str.strip()
)

df = df[
    df["URL"] != ""
]


# ============================================================
# Remove duplicate URLs
# ============================================================

before = len(df)

df = df.drop_duplicates(
    subset=["URL"]
)

after = len(df)

print(
    f"Removed duplicates: {before - after}"
)


# ============================================================
# Save dataset
# ============================================================

output_path = Path(
    __file__
).parent / "phishing_urls.csv"

df.to_csv(
    output_path,
    index=False
)


# ============================================================
# Dataset Summary
# ============================================================

print()
print("Dataset ready!")
print(
    f"Total URLs: {len(df)}"
)

print()
print("Label distribution:")

print(
    df["Label"].value_counts()
)

print()
print("Saved to:")

print(
    output_path
)