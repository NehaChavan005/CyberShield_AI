import os
import json
from datetime import datetime, timezone
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OrdinalEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_PATH = os.path.join(BASE_DIR, "data", "final_dataset.csv")
MODEL_PATH = os.path.join(BASE_DIR, "model", "cybershield_model.pkl")
ENCODER_PATH = os.path.join(BASE_DIR, "model", "encoders.pkl")
FEATURES_PATH = os.path.join(BASE_DIR, "model", "features.pkl")
METADATA_PATH = os.path.join(BASE_DIR, "model", "feature_metadata.json")
CURRENT_VERSION_PATH = os.path.join(BASE_DIR, "model", "current_model.json")
VERSIONS_DIR = os.path.join(BASE_DIR, "model", "versions")


def load_data():
    df = pd.read_csv(DATA_PATH)
    print("Dataset loaded:", df.shape)
    return df


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _build_version_id() -> str:
    return datetime.now(timezone.utc).strftime("model_%Y%m%d_%H%M%S_%f")


def preprocess_and_encode(df):
    # Drop helper column if present
    df.drop(columns=["dataset_source"], inplace=True, errors="ignore")

    # Define columns to exclude from encoding (keep as-is or engineer separately)
    exclude_cols = ["timestamp", "source_ip", "destination_ip"]

    # Determine feature columns (exclude label)
    feature_cols = [c for c in df.columns if c != "label"]

    # Determine categorical columns (object dtype) excluding excluded ones
    categorical = [c for c in feature_cols if df[c].dtype == "object" and c not in exclude_cols]
    numeric = [c for c in feature_cols if c not in categorical]

    encoders = {}

    # Fit separate OrdinalEncoder per categorical column
    for col in categorical:
        oe = OrdinalEncoder(dtype=int)
        values = df[[col]].astype(str).fillna("__MISSING__")
        oe.fit(values)
        df[col] = oe.transform(values).astype(int)
        # Save classes list for this column
        encoders[col] = {"classes": oe.categories_[0].astype(str).tolist()}

    # For numeric columns, coerce types
    for col in numeric:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    metadata = {
        "feature_columns": feature_cols,
        "categorical": categorical,
        "numeric": numeric,
        "excluded": exclude_cols
    }

    return df, encoders, metadata


def _save_model_artifacts(
    model,
    encoders,
    expected_columns,
    metadata,
    version_id: str,
    evaluation: dict,
    source_summary: dict | None = None,
    triggered_by: str = "manual",
):
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    os.makedirs(VERSIONS_DIR, exist_ok=True)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(encoders, ENCODER_PATH)
    joblib.dump(expected_columns, FEATURES_PATH)
    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    version_dir = os.path.join(VERSIONS_DIR, version_id)
    os.makedirs(version_dir, exist_ok=True)
    version_model_path = os.path.join(version_dir, "cybershield_model.pkl")
    version_encoder_path = os.path.join(version_dir, "encoders.pkl")
    version_features_path = os.path.join(version_dir, "features.pkl")
    version_metadata_path = os.path.join(version_dir, "feature_metadata.json")
    version_manifest_path = os.path.join(version_dir, "manifest.json")

    joblib.dump(model, version_model_path)
    joblib.dump(encoders, version_encoder_path)
    joblib.dump(expected_columns, version_features_path)
    with open(version_metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    manifest = {
        "version_id": version_id,
        "trained_at": _utc_now(),
        "triggered_by": triggered_by,
        "model_type": type(model).__name__,
        "dataset_path": DATA_PATH,
        "sample_count": metadata.get("sample_count", 0),
        "feature_count": len(expected_columns),
        "label_distribution": metadata.get("label_distribution", {}),
        "evaluation": evaluation,
        "source_summary": source_summary or {},
        "artifacts": {
            "model": version_model_path,
            "encoders": version_encoder_path,
            "features": version_features_path,
            "metadata": version_metadata_path,
        },
    }
    with open(version_manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    with open(CURRENT_VERSION_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print("\nModel saved to:", MODEL_PATH)
    print("Encoders saved to:", ENCODER_PATH)
    print("Features saved to:", FEATURES_PATH)
    print("Metadata saved to:", METADATA_PATH)
    print("Current model manifest saved to:", CURRENT_VERSION_PATH)
    print("Versioned model artifacts saved to:", version_dir)

    return manifest


def train(df: pd.DataFrame | None = None, source_summary: dict | None = None, triggered_by: str = "manual"):
    if df is None:
        df = load_data()

    df = df.copy()
    df, encoders, metadata = preprocess_and_encode(df)

    X = df.drop("label", axis=1)
    y = df["label"]

    expected_columns = X.columns.tolist()

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=150, max_depth=10, random_state=42)
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    evaluation = classification_report(y_test, predictions, output_dict=True, zero_division=0)

    print("\nModel Evaluation\n")
    print(classification_report(y_test, predictions, zero_division=0))

    metadata["sample_count"] = int(len(df))
    metadata["label_distribution"] = {
        str(key): int(value) for key, value in y.value_counts(dropna=False).to_dict().items()
    }
    version_id = _build_version_id()
    return _save_model_artifacts(
        model=model,
        encoders=encoders,
        expected_columns=expected_columns,
        metadata=metadata,
        version_id=version_id,
        evaluation=evaluation,
        source_summary=source_summary,
        triggered_by=triggered_by,
    )


if __name__ == "__main__":
    train()
