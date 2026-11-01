
from pathlib import Path
import json
import time
import warnings

import joblib
import numpy as np
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


# ==================================================
# THREATPULSE AI - BINARY INTRUSION DETECTION
# ==================================================

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "datasets" / "uploads"
MODEL_DIR = BASE_DIR / "models"

TRAIN_FILE = DATA_DIR / "train_data.csv"
TEST_FILE = DATA_DIR / "test_data.csv"

MODEL_DIR.mkdir(parents=True, exist_ok=True)

# Start with a manageable sample to reduce RAM usage.
MAX_TRAIN_ROWS = 100_000
MAX_TEST_ROWS = 30_000
RANDOM_STATE = 42

# These columns must not be used as model features.
# IMPORTANT: Label is deliberately NOT in this list.
EXCLUDED_FEATURES = [
    "srcip",
    "dstip",
    "Stime",
    "Ltime",
    "attack_cat",
]

warnings.filterwarnings("ignore", category=FutureWarning)


def load_dataset(path, max_rows):
    """Read a limited number of rows and validate the target."""

    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {path}\n"
            "Check that the CSV is inside datasets/uploads/."
        )

    print(f"Reading {path.name} (up to {max_rows:,} rows)...")

    df = pd.read_csv(
        path,
        nrows=max_rows,
        low_memory=False,
    )

    # Remove accidental spaces around column names.
    df.columns = df.columns.astype(str).str.strip()

    # Handle target column name case-insensitively.
    label_matches = [
        col for col in df.columns
        if col.casefold() == "label"
    ]

    if not label_matches:
        raise ValueError(
            f"No Label column in {path.name}. "
            f"Found columns: {df.columns.tolist()}"
        )

    if label_matches[0] != "Label":
        df = df.rename(columns={label_matches[0]: "Label"})

    # Convert target values to numeric binary labels.
    labels = pd.to_numeric(df["Label"], errors="coerce")
    valid = labels.isin([0, 1])

    df = df.loc[valid].copy()
    df["Label"] = labels.loc[valid].astype("int8")

    if df.empty:
        raise ValueError(
            f"No valid Label values (0 or 1) in {path.name}."
        )

    # Normalize categorical strings and infinities.
    for col in df.select_dtypes(
        include=["object", "string"]
    ).columns:
        df[col] = df[col].astype("object")
        df[col] = df[col].map(
            lambda value: (
                value.strip()
                if isinstance(value, str)
                else value
            )
        )
        df[col] = df[col].replace("", np.nan)

    numeric_cols = df.select_dtypes(
        include=["number"]
    ).columns

    df[numeric_cols] = df[numeric_cols].replace(
        [np.inf, -np.inf], np.nan
    )

    print(f"Loaded rows: {len(df):,}")
    print("Label distribution:", df["Label"].value_counts().to_dict())

    if df["Label"].nunique() < 2:
        raise ValueError(
            f"{path.name} sample contains only one label. "
            "A representative sample of both classes is needed."
        )

    return df


def build_features(df):
    """Separate target from features and remove identifiers."""

    y = df["Label"].copy()

    X = df.drop(
        columns=[
            "Label",
            *EXCLUDED_FEATURES,
        ],
        errors="ignore",
    ).copy()

    # Convert boolean feature columns to integers.
    for col in X.select_dtypes(include=["bool"]).columns:
        X[col] = X[col].astype("int8")

    # Preserve text and categorical columns.
    for col in X.columns:
        if (
            pd.api.types.is_object_dtype(X[col])
            or pd.api.types.is_string_dtype(X[col])
            or isinstance(X[col].dtype, pd.CategoricalDtype)
        ):
            X[col] = X[col].astype("object")
            continue

        # Convert remaining columns to numeric.
        X[col] = pd.to_numeric(X[col], errors="coerce")

    if X.shape[1] == 0:
        raise ValueError("No usable feature columns remain.")

    return X, y


def main():
    start = time.time()

    print("=" * 55)
    print("ThreatPulse AI - Model Training")
    print("=" * 55)

    # 1. Load limited samples to avoid loading millions of rows.
    train_df = load_dataset(TRAIN_FILE, MAX_TRAIN_ROWS)
    test_df = load_dataset(TEST_FILE, MAX_TEST_ROWS)

    # 2. Prepare features and target separately.
    X_train, y_train = build_features(train_df)
    X_test, y_test = build_features(test_df)

    # Match test columns to training columns.
    X_test = X_test.reindex(columns=X_train.columns)

    # Replace unsupported pandas missing values with NumPy NaN.
    for col in X_train.columns:
        if X_train[col].dtype == "object":
            X_train[col] = X_train[col].where(
                X_train[col].notna(), np.nan
            )
            X_test[col] = X_test[col].where(
                X_test[col].notna(), np.nan
            )

    numeric_cols = X_train.select_dtypes(
        include=["number"]
    ).columns.tolist()

    categorical_cols = [
        col for col in X_train.columns
        if col not in numeric_cols
    ]

    print("\nFeature summary")
    print("Training rows:", len(X_train))
    print("Testing rows:", len(X_test))
    print("Numeric features:", len(numeric_cols))
    print("Categorical features:", len(categorical_cols))

    if y_train.nunique() < 2:
        raise ValueError(
            "Training sample has only one class. "
            "Please use a representative sample containing labels 0 and 1."
        )

    if y_test.nunique() < 2:
        raise ValueError(
            "Test sample has only one class. "
            "A test sample containing labels 0 and 1 is required."
        )

    # 3. Build preprocessing pipelines.
    transformers = []

    if numeric_cols:
        numeric_pipeline = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler(with_mean=False)),
        ])

        transformers.append(
            ("numeric", numeric_pipeline, numeric_cols)
        )

    if categorical_cols:
        categorical_pipeline = Pipeline([
            (
                "imputer",
                SimpleImputer(strategy="most_frequent"),
            ),
            (
                "onehot",
                OneHotEncoder(
                    handle_unknown="ignore",
                    min_frequency=25,
                    sparse_output=True,
                ),
            ),
        ])

        transformers.append(
            ("categorical", categorical_pipeline, categorical_cols)
        )

    preprocessing = ColumnTransformer(
        transformers=transformers,
        remainder="drop",
    )

    # 4. Create a memory-friendly classifier.
    classifier = SGDClassifier(
        loss="log_loss",
        class_weight="balanced",
        max_iter=20,
        tol=1e-3,
        random_state=RANDOM_STATE,
    )

    model = Pipeline([
        ("preprocessing", preprocessing),
        ("classifier", classifier),
    ])

    # 5. Train only on training data.
    print("\nTraining model...")
    model.fit(X_train, y_train)
    print("Training completed.")

    # 6. Evaluate on the separate test sample.
    print("\nEvaluating model...")
    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(
        y_test, predictions, pos_label=1, zero_division=0
    )
    recall = recall_score(
        y_test, predictions, pos_label=1, zero_division=0
    )
    f1 = f1_score(
        y_test, predictions, pos_label=1, zero_division=0
    )

    matrix = confusion_matrix(
        y_test, predictions, labels=[0, 1]
    )

    report = classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["Normal", "Attack"],
        output_dict=True,
        zero_division=0,
    )

    # 7. Save the trained model and measured metrics.
    model_path = MODEL_DIR / "threatpulse_model.joblib"
    metrics_path = MODEL_DIR / "evaluation_metrics.json"

    joblib.dump(model, model_path)

    metrics = {
        "model": "SGDClassifier with log_loss",
        "task": "Binary intrusion detection",
        "random_state": RANDOM_STATE,
        "training_rows_used": int(len(X_train)),
        "testing_rows_used": int(len(X_test)),
        "accuracy": float(accuracy),
        "precision_attack": float(precision),
        "recall_attack": float(recall),
        "f1_attack": float(f1),
        "confusion_matrix_labels": ["Normal", "Attack"],
        "confusion_matrix": matrix.tolist(),
        "classification_report": report,
        "features_used": list(X_train.columns),
        "sampling_note": (
            "This initial run uses the first configured number of "
            "valid rows from each CSV. Results may not represent the "
            "full datasets if rows are ordered by label."
        ),
    }

    with open(metrics_path, "w", encoding="utf-8") as file:
        json.dump(metrics, file, indent=2)

    # 8. Print the actual results.
    print("\n" + "=" * 55)
    print("EVALUATION RESULTS")
    print("=" * 55)
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-score:  {f1:.4f}")

    print("\nConfusion matrix")
    print("Rows = actual; columns = predicted")
    print("Order: Normal, Attack")
    print(matrix)

    print("\nClassification report")
    print(classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["Normal", "Attack"],
        zero_division=0,
    ))

    print("\nSaved model:", model_path)
    print("Saved metrics:", metrics_path)
    print(f"Elapsed time: {time.time() - start:.1f} seconds")
    print("\nInitial training run finished.")


if __name__ == "__main__":
    main()
