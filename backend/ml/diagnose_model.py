import sys
from pathlib import Path

import joblib
import pandas as pd


# ============================================================
# PATH
# ============================================================

BACKEND_DIR = Path(__file__).resolve().parents[1]

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


from app.services.feature_extractor import extract_features


# ============================================================
# LOAD MODEL + DATA
# ============================================================

MODEL_PATH = (
    BACKEND_DIR
    / "ml"
    / "models"
    / "random_forest_model.joblib"
)

DATASET_PATH = (
    BACKEND_DIR
    / "ml"
    / "dataset"
    / "sentinel_features.csv"
)


model_data = joblib.load(MODEL_PATH)

model = model_data["model"]

feature_columns = model_data["features"]

df = pd.read_csv(DATASET_PATH)


# ============================================================
# TEST URL
# ============================================================

url = "https://google.com"

features = extract_features(url)


row = {}

for feature in feature_columns:

    value = features.get(feature, 0)

    if isinstance(value, bool):
        value = int(value)

    try:
        value = int(value)
    except (TypeError, ValueError):
        value = 0

    row[feature] = value


X = pd.DataFrame(
    [row],
    columns=feature_columns
)


# ============================================================
# MODEL OUTPUT
# ============================================================

prediction = model.predict(X)[0]

probability = model.predict_proba(X)[0]

class_probabilities = dict(
    zip(
        model.classes_,
        probability
    )
)


print()
print("========================================")
print("SENTINEL ML DIAGNOSTIC")
print("========================================")

print()
print("Test URL:")
print(url)

print()
print("Prediction:")
print(prediction)

print()
print("Class probabilities:")

for class_id, probability in class_probabilities.items():

    print(
        f"Class {class_id}: "
        f"{probability * 100:.2f}%"
    )


# ============================================================
# TEST FEATURES
# ============================================================

print()
print("Google feature vector:")

for feature in feature_columns:

    print(
        f"{feature:<30} "
        f"{row[feature]}"
    )


# ============================================================
# DATASET STATISTICS
# ============================================================

print()
print("========================================")
print("DATASET FEATURE STATISTICS")
print("========================================")


for label in [0, 1]:

    class_df = df[
        df["Label"] == label
    ]

    print()
    print(
        f"Label {label}"
    )

    print(
        f"Samples: {len(class_df)}"
    )

    print()

    for feature in feature_columns:

        mean_value = class_df[
            feature
        ].mean()

        print(
            f"{feature:<30} "
            f"{mean_value:.4f}"
        )