import json
import os
from datetime import datetime, timezone

import pandas as pd

from model.train_model import DATA_PATH, CURRENT_VERSION_PATH, VERSIONS_DIR, train


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FEEDBACK_STORE_PATH = os.path.join(BASE_DIR, "data", "model_feedback.json")
RETRAINING_DATA_PATH = os.path.join(BASE_DIR, "data", "retraining_dataset.csv")


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _default_feedback_store() -> dict:
    return {
        "feedback": [],
        "updated_at": None,
    }


def _normalize_label(value) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return 1 if int(value) == 1 else 0

    text = str(value or "").strip().lower()
    if text in {"1", "attack", "attacker", "malicious", "true", "yes"}:
        return 1
    if text in {"0", "normal", "benign", "false", "no"}:
        return 0
    raise ValueError("Label must be one of: 0, 1, normal, attack, benign, malicious.")


def load_feedback_store() -> dict:
    if not os.path.exists(FEEDBACK_STORE_PATH):
        return _default_feedback_store()

    try:
        with open(FEEDBACK_STORE_PATH, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return _default_feedback_store()

    store = _default_feedback_store()
    if isinstance(payload, dict):
        store.update(payload)
    if not isinstance(store.get("feedback"), list):
        store["feedback"] = []
    return store


def save_feedback_store(store: dict) -> None:
    os.makedirs(os.path.dirname(FEEDBACK_STORE_PATH), exist_ok=True)
    payload = _default_feedback_store()
    if isinstance(store, dict):
        payload.update(store)
    payload["updated_at"] = _utc_now()
    with open(FEEDBACK_STORE_PATH, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def submit_feedback(
    sample: dict,
    expected_label,
    feedback_source: str = "analyst",
    notes: str | None = None,
    prediction_result: dict | None = None,
) -> dict:
    normalized_label = _normalize_label(expected_label)
    feedback_id = f"fb-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"

    entry = {
        "feedback_id": feedback_id,
        "recorded_at": _utc_now(),
        "feedback_source": feedback_source,
        "expected_label": normalized_label,
        "expected_verdict": "attack" if normalized_label == 1 else "normal",
        "notes": notes or "",
        "sample": dict(sample or {}),
        "prediction_snapshot": {
            "prediction": (prediction_result or {}).get("prediction"),
            "probability": (prediction_result or {}).get("probability"),
            "ai_analysis": (prediction_result or {}).get("ai_analysis"),
            "model_version": (prediction_result or {}).get("model_version"),
        },
    }

    store = load_feedback_store()
    store["feedback"].append(entry)
    store["feedback"] = store["feedback"][-2000:]
    save_feedback_store(store)
    return entry


def _prepare_feedback_dataframe(feedback_entries: list[dict], base_columns: list[str]) -> pd.DataFrame:
    rows = []
    for entry in feedback_entries:
        sample = dict(entry.get("sample") or {})
        sample["label"] = entry.get("expected_label", 0)
        for column in base_columns:
            sample.setdefault(column, None)
        rows.append({column: sample.get(column) for column in base_columns})

    if not rows:
        return pd.DataFrame(columns=base_columns)

    feedback_df = pd.DataFrame(rows)
    feedback_df["label"] = pd.to_numeric(feedback_df["label"], errors="coerce").fillna(0).astype(int)
    return feedback_df


def build_retraining_dataset() -> tuple[pd.DataFrame, dict]:
    base_df = pd.read_csv(DATA_PATH)
    feedback_store = load_feedback_store()
    feedback_entries = feedback_store.get("feedback", [])

    base_columns = base_df.columns.tolist()
    feedback_df = _prepare_feedback_dataframe(feedback_entries, base_columns)
    combined_df = pd.concat([base_df, feedback_df], ignore_index=True)
    os.makedirs(os.path.dirname(RETRAINING_DATA_PATH), exist_ok=True)
    combined_df.to_csv(RETRAINING_DATA_PATH, index=False)

    summary = {
        "base_samples": int(len(base_df)),
        "feedback_samples": int(len(feedback_df)),
        "combined_samples": int(len(combined_df)),
        "retraining_dataset_path": RETRAINING_DATA_PATH,
    }
    return combined_df, summary


def retrain_model_from_feedback(min_feedback_samples: int = 1, triggered_by: str = "feedback_loop") -> dict:
    feedback_store = load_feedback_store()
    feedback_count = len(feedback_store.get("feedback", []))
    if feedback_count < min_feedback_samples:
        raise ValueError(
            f"At least {min_feedback_samples} feedback samples are required before retraining. "
            f"Current feedback samples: {feedback_count}."
        )

    combined_df, summary = build_retraining_dataset()
    manifest = train(df=combined_df, source_summary=summary, triggered_by=triggered_by)
    return {
        "message": "Retraining completed successfully.",
        "feedback_samples_used": feedback_count,
        "dataset_summary": summary,
        "model_manifest": manifest,
    }


def list_model_versions() -> list[dict]:
    if not os.path.exists(VERSIONS_DIR):
        return []

    versions = []
    for name in sorted(os.listdir(VERSIONS_DIR), reverse=True):
        manifest_path = os.path.join(VERSIONS_DIR, name, "manifest.json")
        if not os.path.exists(manifest_path):
            continue
        try:
            with open(manifest_path, "r", encoding="utf-8") as handle:
                versions.append(json.load(handle))
        except (OSError, json.JSONDecodeError):
            continue
    return versions


def get_current_model_status() -> dict:
    current_manifest = {}
    if os.path.exists(CURRENT_VERSION_PATH):
        try:
            with open(CURRENT_VERSION_PATH, "r", encoding="utf-8") as handle:
                current_manifest = json.load(handle)
        except (OSError, json.JSONDecodeError):
            current_manifest = {}

    feedback_store = load_feedback_store()
    versions = list_model_versions()
    return {
        "current_model": current_manifest,
        "feedback_samples": len(feedback_store.get("feedback", [])),
        "feedback_store_path": FEEDBACK_STORE_PATH,
        "retraining_dataset_path": RETRAINING_DATA_PATH,
        "available_versions": len(versions),
        "latest_versions": versions[:5],
    }
