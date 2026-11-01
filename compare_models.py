
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression, SGDClassifier
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
from sklearn.ensemble import RandomForestClassifier


# --------------------------------------------------
# ThreatPulse AI - Model Comparison
# Existing model and metrics files are NOT overwritten.
# --------------------------------------------------

ROOT = Path(__file__).resolve().parent
TRAIN_FILE = ROOT / "datasets" / "uploads" / "train_data.csv"
TEST_FILE = ROOT / "datasets" / "uploads" / "test_data.csv"
OUTPUT_DIR = ROOT / "reports"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

TRAIN_ROWS = 100_000
TEST_ROWS = 30_000
RANDOM_STATE = 42

EXCLUDED_FEATURES = ["dstip", "Stime", "Ltime", "attack_cat"]


def load_data(path, max_rows):
    if not path.exists():
        raise FileNotFoundError(f"Dataset file not found: {path}")

    df = pd.read_csv(path, nrows=max_rows, low_memory=False)
    df.columns = df.columns.astype(str).str.strip()

    if "Label" not in df.columns:
        raise ValueError(f"'Label' column is missing in {path.name}")

    labels = pd.to_numeric(df["Label"], errors="coerce")
    valid = labels.isin([0, 1])
    df = df.loc[valid].copy()
    df["Label"] = labels.loc[valid].astype(int)

    if df.empty:
        raise ValueError(f"No valid 0/1 labels found in {path.name}")

    return df


def prepare_features(df):
    y = df["Label"].astype(int)
    X = df.drop(columns=["Label"], errors="ignore")
    X = X.drop(columns=EXCLUDED_FEATURES, errors="ignore")

    # Convert boolean columns to integers.
    for col in X.select_dtypes(include=["bool"]).columns:
        X[col] = X[col].astype("int8")

    # Treat infinity as missing in numeric columns.
    numeric_cols = X.select_dtypes(include=["number"]).columns
    X[numeric_cols] = X[numeric_cols].replace(
        [np.inf, -np.inf], np.nan
    )

    # Normalize text and replace common missing-value strings.
    categorical_cols = X.select_dtypes(
        include=["object", "category", "string"]
    ).columns

    for col in categorical_cols:
        X[col] = X[col].astype("string").str.strip()
        X[col] = X[col].replace(
            {"": pd.NA, "nan": pd.NA, "None": pd.NA}
        )

    return X, y


def build_pipeline(model, numeric_cols, categorical_cols):
    transformers = []

    if len(numeric_cols):
        numeric_pipeline = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler(with_mean=False)),
        ])
        transformers.append(
            ("numeric", numeric_pipeline, numeric_cols)
        )

    if len(categorical_cols):
        categorical_pipeline = Pipeline([
            ("imputer", SimpleImputer(strategy="most_frequent")),
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

    return Pipeline([
        ("preprocessing", preprocessing),
        ("classifier", model),
    ])


def main():
    print("=" * 65)
    print("ThreatPulse AI - ML Model Comparison")
    print("=" * 65)

    print("\n[1/5] Loading datasets...")
    train_df = load_data(TRAIN_FILE, TRAIN_ROWS)
    test_df = load_data(TEST_FILE, TEST_ROWS)

    X_train, y_train = prepare_features(train_df)
    X_test, y_test = prepare_features(test_df)

    # Align test columns to training columns.
    X_test = X_test.reindex(columns=X_train.columns)

    if y_train.nunique() < 2 or y_test.nunique() < 2:
        raise ValueError(
            "Both Normal (0) and Attack (1) labels are needed "
            "in the training and test samples."
        )

    print(f"Training rows: {len(X_train):,}")
    print(f"Testing rows:  {len(X_test):,}")
    print(f"Training labels: {y_train.value_counts().to_dict()}")
    print(f"Testing labels:  {y_test.value_counts().to_dict()}")

    numeric_cols = list(
        X_train.select_dtypes(include=["number"]).columns
    )
    categorical_cols = list(
        X_train.select_dtypes(
            include=["object", "category", "string"]
        ).columns
    )

    print(f"Numeric features: {len(numeric_cols)}")
    print(f"Categorical features: {len(categorical_cols)}")

    models = {
        "SGDClassifier": SGDClassifier(
            loss="log_loss",
            class_weight="balanced",
            max_iter=20,
            tol=1e-3,
            random_state=RANDOM_STATE,
        ),
        "LogisticRegression": LogisticRegression(
            class_weight="balanced",
            max_iter=100,
            solver="saga",
            random_state=RANDOM_STATE,
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=100,
            max_depth=16,
            min_samples_leaf=2,
            class_weight="balanced_subsample",
            random_state=RANDOM_STATE,
            n_jobs=-1,
        ),
    }

    results = []

    print("\n[2/5] Training and evaluating models...")
    print("This may take several minutes, depending on your PC.")

    for name, estimator in models.items():
        print(f"\n--- {name} ---")

        pipeline = build_pipeline(
            clone(estimator), numeric_cols, categorical_cols
        )

        try:
            start_train = time.perf_counter()
            pipeline.fit(X_train, y_train)
            training_seconds = time.perf_counter() - start_train

            start_predict = time.perf_counter()
            predictions = pipeline.predict(X_test)
            prediction_seconds = time.perf_counter() - start_predict

            tn, fp, fn, tp = confusion_matrix(
                y_test, predictions, labels=[0, 1]
            ).ravel()

            result = {
                "model": name,
                "accuracy": float(accuracy_score(y_test, predictions)),
                "precision_attack": float(
                    precision_score(
                        y_test, predictions, zero_division=0
                    )
                ),
                "recall_attack": float(
                    recall_score(
                        y_test, predictions, zero_division=0
                    )
                ),
                "f1_attack": float(
                    f1_score(
                        y_test, predictions, zero_division=0
                    )
                ),
                "false_positive_rate": float(
                    fp / (fp + tn) if (fp + tn) else 0.0
                ),
                "true_negative": int(tn),
                "false_positive": int(fp),
                "false_negative": int(fn),
                "true_positive": int(tp),
                "training_seconds": round(training_seconds, 3),
                "prediction_seconds": round(prediction_seconds, 3),
                "classification_report": classification_report(
                    y_test,
                    predictions,
                    labels=[0, 1],
                    target_names=["Normal", "Attack"],
                    output_dict=True,
                    zero_division=0,
                ),
            }

            results.append(result)

            print(f"Accuracy:           {result['accuracy']:.4f}")
            print(f"Attack Precision:   {result['precision_attack']:.4f}")
            print(f"Attack Recall:      {result['recall_attack']:.4f}")
            print(f"Attack F1-score:    {result['f1_attack']:.4f}")
            print(f"False Positive Rate:{result['false_positive_rate']:.4f}")
            print(f"Training time:      {training_seconds:.2f} sec")
            print(f"Prediction time:    {prediction_seconds:.2f} sec")

            # Free resources before moving to the next model.
            del pipeline, predictions

        except Exception as exc:
            print(f"ERROR: {name} failed: {exc}")
            results.append({
                "model": name,
                "error": str(exc),
            })

    print("\n[3/5] Preparing comparison results...")
    successful = [
        result for result in results if "error" not in result
    ]

    if not successful:
        raise RuntimeError(
            "All models failed. Review the error messages above."
        )

    successful.sort(key=lambda item: item["f1_attack"], reverse=True)

    comparison_columns = [
        "model",
        "accuracy",
        "precision_attack",
        "recall_attack",
        "f1_attack",
        "false_positive_rate",
        "training_seconds",
        "prediction_seconds",
    ]

    comparison_df = pd.DataFrame(successful)[comparison_columns]

    print("\n[4/5] Comparison table (sorted by Attack F1-score):")
    print(comparison_df.to_string(index=False, float_format=lambda x: f"{x:.4f}"))

    json_path = OUTPUT_DIR / "model_comparison.json"
    csv_path = OUTPUT_DIR / "model_comparison.csv"

    metadata = {
        "project": "ThreatPulse AI",
        "training_file": str(TRAIN_FILE.relative_to(ROOT)),
        "testing_file": str(TEST_FILE.relative_to(ROOT)),
        "training_rows_loaded_before_label_filter": TRAIN_ROWS,
        "testing_rows_loaded_before_label_filter": TEST_ROWS,
        "actual_training_rows": len(X_train),
        "actual_testing_rows": len(X_test),
        "random_state": RANDOM_STATE,
        "note": (
            "Uses the first configured rows from each CSV, matching "
            "the current baseline workflow. Results may be affected "
            "by row ordering and are not full-dataset evaluation."
        ),
        "results": results,
        "ranking_by_attack_f1": [
            result["model"] for result in successful
        ],
    }

    with open(json_path, "w", encoding="utf-8") as file:
        json.dump(metadata, file, indent=2)

    comparison_df.to_csv(csv_path, index=False)

    print("\n[5/5] Completed.")
    print(f"JSON report: {json_path}")
    print(f"CSV report:  {csv_path}")
    print("\nExisting model and evaluation_metrics.json were not modified.")


if __name__ == "__main__":
    main()
