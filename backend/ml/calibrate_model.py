import sys
from pathlib import Path

import joblib
import pandas as pd

from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator

from sklearn.model_selection import train_test_split

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
)


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

CALIBRATED_MODEL_PATH = (
    BACKEND_DIR
    / "ml"
    / "models"
    / "calibrated_random_forest.joblib"
)


# ============================================================
# CONFIGURATION
# ============================================================

RANDOM_STATE = 42

CALIBRATION_SIZE = 0.20


# ============================================================
# LOAD ORIGINAL MODEL
# ============================================================

print("Loading original Random Forest...")

if not MODEL_PATH.exists():

    raise FileNotFoundError(
        f"Original model not found:\n{MODEL_PATH}"
    )


model_data = joblib.load(
    MODEL_PATH
)

base_model = model_data["model"]

feature_columns = model_data["features"]


# ============================================================
# LOAD DATASET
# ============================================================

print("Loading Sentinel dataset...")

if not DATASET_PATH.exists():

    raise FileNotFoundError(
        f"Dataset not found:\n{DATASET_PATH}"
    )


df = pd.read_csv(
    DATASET_PATH
)


# ============================================================
# VALIDATE DATASET
# ============================================================

if "Label" not in df.columns:

    raise ValueError(
        "Label column not found in dataset."
    )


missing_features = [
    feature
    for feature in feature_columns
    if feature not in df.columns
]


if missing_features:

    raise ValueError(
        "Missing model features:\n"
        + "\n".join(missing_features)
    )


X = df[
    feature_columns
]

y = df["Label"]


# ============================================================
# CREATE CALIBRATION DATA
# ============================================================

print()
print("Creating calibration dataset...")

X_unused, X_calibration, y_unused, y_calibration = (
    train_test_split(
        X,
        y,
        test_size=CALIBRATION_SIZE,
        random_state=RANDOM_STATE,
        stratify=y
    )
)


print(
    f"Calibration samples: "
    f"{len(X_calibration)}"
)


# ============================================================
# CALIBRATE EXISTING MODEL
# ============================================================

print()
print("Calibrating Random Forest probabilities...")

# ------------------------------------------------------------
# IMPORTANT:
#
# scikit-learn 1.9+ does not support:
#
#     cv="prefit"
#
# Instead, FrozenEstimator is used to tell
# CalibratedClassifierCV that the model is already fitted.
# ------------------------------------------------------------

frozen_model = FrozenEstimator(
    base_model
)


calibrated_model = CalibratedClassifierCV(
    estimator=frozen_model,
    method="sigmoid"
)


calibrated_model.fit(
    X_calibration,
    y_calibration
)


print(
    "Calibration complete."
)


# ============================================================
# PREDICTIONS
# ============================================================

print()
print("Evaluating calibrated model...")

predictions = calibrated_model.predict(
    X_calibration
)


probabilities = calibrated_model.predict_proba(
    X_calibration
)


phishing_probabilities = probabilities[
    :, 1
]


# ============================================================
# METRICS
# ============================================================

accuracy = accuracy_score(
    y_calibration,
    predictions
)

precision = precision_score(
    y_calibration,
    predictions,
    zero_division=0
)

recall = recall_score(
    y_calibration,
    predictions,
    zero_division=0
)

f1 = f1_score(
    y_calibration,
    predictions,
    zero_division=0
)


# ============================================================
# RESULTS
# ============================================================

print()
print("========================================")
print("CALIBRATED MODEL RESULTS")
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
        y_calibration,
        predictions,
        target_names=[
            "Legitimate",
            "Phishing"
        ],
        zero_division=0
    )
)


# ============================================================
# PROBABILITY ANALYSIS
# ============================================================

results = pd.DataFrame({
    "actual": y_calibration.to_numpy(),
    "prediction": predictions,
    "phishing_probability": phishing_probabilities
})


legitimate = results[
    results["actual"] == 0
]

phishing = results[
    results["actual"] == 1
]


# ============================================================
# LEGITIMATE ANALYSIS
# ============================================================

print()
print("========================================")
print("LEGITIMATE URL ANALYSIS")
print("========================================")

print(
    f"Legitimate samples: "
    f"{len(legitimate)}"
)

print(
    f"Average phishing probability: "
    f"{legitimate['phishing_probability'].mean():.2%}"
)

print(
    f">=50% phishing probability: "
    f"{(
        legitimate['phishing_probability'] >= 0.50
    ).sum()}"
)

print(
    f">=90% phishing probability: "
    f"{(
        legitimate['phishing_probability'] >= 0.90
    ).sum()}"
)


# ============================================================
# PHISHING ANALYSIS
# ============================================================

print()
print("========================================")
print("PHISHING URL ANALYSIS")
print("========================================")

print(
    f"Phishing samples: "
    f"{len(phishing)}"
)

print(
    f"Average phishing probability: "
    f"{phishing['phishing_probability'].mean():.2%}"
)

print(
    f">=50% phishing probability: "
    f"{(
        phishing['phishing_probability'] >= 0.50
    ).sum()}"
)

print(
    f">=90% phishing probability: "
    f"{(
        phishing['phishing_probability'] >= 0.90
    ).sum()}"
)


# ============================================================
# CONFUSION MATRIX
# ============================================================

from sklearn.metrics import confusion_matrix


matrix = confusion_matrix(
    y_calibration,
    predictions
)


print()
print("========================================")
print("CONFUSION MATRIX")
print("========================================")

print(matrix)


# ============================================================
# SAVE CALIBRATED MODEL
# ============================================================

print()
print("Saving calibrated model...")

MODEL_PATH.parent.mkdir(
    parents=True,
    exist_ok=True
)


joblib.dump(
    {
        "model": calibrated_model,

        "features": feature_columns,

        "label_mapping": {
            0: "LEGITIMATE",
            1: "PHISHING"
        }
    },
    CALIBRATED_MODEL_PATH
)


print()
print("========================================")
print("CALIBRATED MODEL SAVED")
print("========================================")

print(
    CALIBRATED_MODEL_PATH
)