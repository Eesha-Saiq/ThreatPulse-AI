
import json
import os

import joblib
import numpy as np
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

TRAIN_PATH = "datasets/uploads/train_data.csv"
TEST_PATH = "datasets/uploads/test_data.csv"

MODEL_PATH = "models/threatpulse_live_model.joblib"
METRICS_PATH = "models/threatpulse_live_metrics.json"

TRAIN_SAMPLE_SIZE = 150_000
TEST_SAMPLE_SIZE = 50_000
RANDOM_STATE = 42

FEATURES = [
    "sport", "dsport", "proto", "state",
    "dur", "sbytes", "dbytes", "Spkts", "Dpkts",
    "Sload", "Dload", "sttl", "dttl",
    "smeansz", "dmeansz",
    "synack", "ackdat", "tcprtt",
    "is_sm_ips_ports",
]

CATEGORICAL_FEATURES = [
    "sport", "dsport", "proto", "state"
]

NUMERIC_FEATURES = [
    feature for feature in FEATURES
    if feature not in CATEGORICAL_FEATURES
]


# --------------------------------------------------
# DATA LOADING
# --------------------------------------------------

def load_sample(path, sample_size, dataset_name):

    print(f"\nLoading {dataset_name} dataset...")

    required_columns = FEATURES + ["Label"]

    df = pd.read_csv(
        path,
        usecols=required_columns,
        low_memory=False
    )

    df.columns = df.columns.str.strip()

    df["Label"] = pd.to_numeric(
        df["Label"],
        errors="coerce"
    )

    df = df[df["Label"].isin([0, 1])].copy()

    if len(df) > sample_size:
        df = df.sample(
            n=sample_size,
            random_state=RANDOM_STATE
        )

    # Categorical cleaning
    for column in CATEGORICAL_FEATURES:
        df[column] = (
            df[column]
            .fillna("unknown")
            .astype(str)
            .str.strip()
        )

    df["proto"] = df["proto"].str.lower()
    df["state"] = df["state"].str.upper()

    # Numeric cleaning
    for column in NUMERIC_FEATURES:
        df[column] = pd.to_numeric(
            df[column],
            errors="coerce"
        )

    df[NUMERIC_FEATURES] = (
        df[NUMERIC_FEATURES]
        .replace([np.inf, -np.inf], np.nan)
    )

    X = df[FEATURES].copy()
    y = df["Label"].astype(int).copy()

    print(f"{dataset_name} records: {len(df):,}")
    print("Label distribution:")
    print(y.value_counts().sort_index().to_string())

    return X, y


# --------------------------------------------------
# MODEL TRAINING
# --------------------------------------------------

def main():

    os.makedirs("models", exist_ok=True)

    X_train, y_train = load_sample(
        TRAIN_PATH,
        TRAIN_SAMPLE_SIZE,
        "Training"
    )

    X_test, y_test = load_sample(
        TEST_PATH,
        TEST_SAMPLE_SIZE,
        "Testing"
    )

    categorical_pipeline = Pipeline([
        (
            "imputer",
            SimpleImputer(strategy="most_frequent")
        ),
        (
            "encoder",
            OneHotEncoder(
                handle_unknown="ignore",
                min_frequency=25
            )
        ),
    ])

    numeric_pipeline = Pipeline([
        (
            "imputer",
            SimpleImputer(strategy="median")
        ),
        (
            "scaler",
            StandardScaler(with_mean=False)
        ),
    ])

    preprocessor = ColumnTransformer([
        (
            "categorical",
            categorical_pipeline,
            CATEGORICAL_FEATURES
        ),
        (
            "numeric",
            numeric_pipeline,
            NUMERIC_FEATURES
        ),
    ])

    model = Pipeline([
        ("preprocessor", preprocessor),
        (
            "classifier",
            SGDClassifier(
                loss="log_loss",
                class_weight="balanced",
                max_iter=30,
                tol=1e-3,
                random_state=RANDOM_STATE
            )
        ),
    ])

    print("\nTraining separate Live AI model...")
    model.fit(X_train, y_train)

    print("\nEvaluating on untouched test sample...")

    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(
        y_test, predictions, zero_division=0
    )
    recall = recall_score(
        y_test, predictions, zero_division=0
    )
    f1 = f1_score(
        y_test, predictions, zero_division=0
    )

    matrix = confusion_matrix(
        y_test,
        predictions,
        labels=[0, 1]
    )

    print("\n========== LIVE MODEL RESULTS ==========")
    print(f"Accuracy:  {accuracy * 100:.2f}%")
    print(f"Precision: {precision * 100:.2f}%")
    print(f"Recall:    {recall * 100:.2f}%")
    print(f"F1 Score:  {f1 * 100:.2f}%")

    print("\nConfusion Matrix:")
    print(matrix)

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["Normal", "Potential Attack"],
            zero_division=0
        )
    )

    # Save as a separate candidate model
    joblib.dump(model, MODEL_PATH)

    metrics = {
        "model": "ThreatPulse Live AI",
        "features": FEATURES,
        "training_records": len(X_train),
        "testing_records": len(X_test),
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "confusion_matrix": matrix.tolist(),
        "classes": {
            "0": "Normal",
            "1": "Potential Attack"
        }
    }

    with open(METRICS_PATH, "w") as file:
        json.dump(metrics, file, indent=4)

    print("\nSaved candidate model:", MODEL_PATH)
    print("Saved evaluation:", METRICS_PATH)
    print("\nLive model training completed.")


if __name__ == "__main__":
    main()
