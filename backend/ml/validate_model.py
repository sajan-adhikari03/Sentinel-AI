import sys
from pathlib import Path

import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)
from sklearn.model_selection import train_test_split


# ============================================================
# PATHS
# ============================================================

BACKEND_DIR = Path(__file__).resolve().parents[1]

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


DATASET_PATH = (
    BACKEND_DIR
    / "ml"
    / "dataset"
    / "sentinel_features.csv"
)

MODEL_PATH = (
    BACKEND_DIR
    / "ml"
    / "models"
    / "random_forest_model.joblib"
)


# ============================================================
# CONFIGURATION
# ============================================================

RANDOM_STATE = 42
VALIDATION_SIZE = 0.20


# ============================================================
# LOAD MODEL
# ============================================================

print("Loading trained model...")

model_data = joblib.load(
    MODEL_PATH
)

model = model_data["model"]

feature_columns = model_data["features"]


# ============================================================
# LOAD DATASET
# ============================================================

print("Loading dataset...")

df = pd.read_csv(
    DATASET_PATH
)

X = df[
    feature_columns
]

y = df["Label"]


# ============================================================
# CREATE VALIDATION SET
# ============================================================

print()
print("Creating validation set...")

_, X_validation, _, y_validation = train_test_split(
    X,
    y,
    test_size=VALIDATION_SIZE,
    random_state=RANDOM_STATE,
    stratify=y
)


print(
    f"Validation samples: {len(X_validation)}"
)


# ============================================================
# PREDICTION
# ============================================================

print()
print("Running model validation...")

y_prediction = model.predict(
    X_validation
)


# ============================================================
# METRICS
# ============================================================

accuracy = accuracy_score(
    y_validation,
    y_prediction
)

precision = precision_score(
    y_validation,
    y_prediction,
    zero_division=0
)

recall = recall_score(
    y_validation,
    y_prediction,
    zero_division=0
)

f1 = f1_score(
    y_validation,
    y_prediction,
    zero_division=0
)


# ============================================================
# RESULTS
# ============================================================

print()
print("========================================")
print("MODEL VALIDATION RESULTS")
print("========================================")

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


# ============================================================
# CLASSIFICATION REPORT
# ============================================================

print()
print("Classification Report:")

print(
    classification_report(
        y_validation,
        y_prediction,
        target_names=[
            "Legitimate",
            "Phishing"
        ],
        zero_division=0
    )
)


# ============================================================
# CONFUSION MATRIX
# ============================================================

matrix = confusion_matrix(
    y_validation,
    y_prediction
)

print()
print("Confusion Matrix:")

print(matrix)


# ============================================================
# PROBABILITY ANALYSIS
# ============================================================

probabilities = model.predict_proba(
    X_validation
)

phishing_probabilities = probabilities[
    :, 1
]


validation_results = pd.DataFrame({
    "actual": y_validation.values,
    "prediction": y_prediction,
    "phishing_probability": phishing_probabilities
})


# ============================================================
# LEGITIMATE URL ANALYSIS
# ============================================================

legitimate = validation_results[
    validation_results["actual"] == 0
]

legitimate_false_positive = legitimate[
    legitimate["prediction"] == 1
]


print()
print("========================================")
print("LEGITIMATE URL ANALYSIS")
print("========================================")

print(
    f"Legitimate samples: "
    f"{len(legitimate)}"
)

print(
    f"False positives: "
    f"{len(legitimate_false_positive)}"
)

print(
    f"False-positive rate: "
    f"{len(legitimate_false_positive) / len(legitimate):.4%}"
)

print(
    f"Average phishing probability: "
    f"{legitimate['phishing_probability'].mean():.2%}"
)


# ============================================================
# PHISHING URL ANALYSIS
# ============================================================

phishing = validation_results[
    validation_results["actual"] == 1
]

phishing_correct = phishing[
    phishing["prediction"] == 1
]


print()
print("========================================")
print("PHISHING URL ANALYSIS")
print("========================================")

print(
    f"Phishing samples: "
    f"{len(phishing)}"
)

print(
    f"Correctly detected: "
    f"{len(phishing_correct)}"
)

print(
    f"Average phishing probability: "
    f"{phishing['phishing_probability'].mean():.2%}"
)


# ============================================================
# HIGH-CONFIDENCE LEGITIMATE FALSE POSITIVES
# ============================================================

high_confidence_false_positive = legitimate[
    legitimate["phishing_probability"] >= 0.90
]


print()
print("========================================")
print("HIGH-CONFIDENCE FALSE POSITIVES")
print("========================================")

print(
    f"Legitimate URLs predicted as "
    f">=90% phishing: "
    f"{len(high_confidence_false_positive)}"
)


# ============================================================
# SUMMARY
# ============================================================

print()
print("========================================")
print("VALIDATION COMPLETE")
print("========================================")