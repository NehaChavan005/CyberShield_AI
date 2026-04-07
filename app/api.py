import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel

from auth.api import get_current_user
from auth.security import create_access_token
from auth.store import authenticate_user
from alerts.alert_manager import get_alert_dashboard_snapshot, get_recent_alerts, load_alert_store
from model.model_lifecycle import (
    get_current_model_status,
    list_model_versions,
    retrain_model_from_feedback,
    submit_feedback,
)
from utils.attack_predictor import predict_attack
from utils.forensics import analyze_attack_history, export_attack_history_csv, export_attack_history_pdf, load_attack_history
from utils.packet_capture import run_dataset_packet_capture
from utils.threat_intelligence import add_to_blacklist, enrich_threat_intelligence, load_blacklist_db
from utils.vulnerability_scanner import scan_target


app = FastAPI(title="CyberShield-AI API", version="1.0.0")


class LoginRequest(BaseModel):
    username: str
    password: str


class PredictionRequest(BaseModel):
    source_ip: str | None = None
    destination_ip: str | None = None
    protocol: str
    port: int
    packet_size: int
    request_rate: int
    failed_logins: int
    malware_signature: str = "none"
    traffic_type: str = "normal"
    attack_type: str = "none"
    suspicious_pid: int | None = None
    suspicious_process_name: str | None = None
    auto_remediate: bool = False


class ThreatIntelRequest(BaseModel):
    source_ip: str | None = None
    destination_ip: str | None = None
    malware_signature: str | None = None
    attack_type: str | None = None


class BlacklistRequest(BaseModel):
    indicator_type: str
    value: str
    source: str = "manual"
    reason: str


class VulnerabilityScanRequest(BaseModel):
    target: str
    ports: list[int] | None = None
    timeout: float = 0.35


class PacketCaptureRequest(BaseModel):
    packet_count: int = 10
    interval_seconds: float = 0.0
    attack_only: bool = False
    auto_remediate: bool = False


class ModelFeedbackRequest(BaseModel):
    sample: dict
    expected_label: int | str
    feedback_source: str = "analyst"
    notes: str | None = None
    include_prediction_snapshot: bool = True


class ModelRetrainRequest(BaseModel):
    min_feedback_samples: int = 1


@app.get("/health")
def healthcheck():
    return {"status": "ok"}


@app.get("/model/status")
def get_model_status(current_user: dict = Depends(get_current_user)):
    return {"user": current_user, "result": get_current_model_status()}


@app.get("/model/versions")
def get_model_versions(current_user: dict = Depends(get_current_user)):
    return {"user": current_user, "result": list_model_versions()}


@app.post("/model/feedback")
def create_model_feedback(
    payload: ModelFeedbackRequest,
    current_user: dict = Depends(get_current_user),
):
    prediction_result = None
    if payload.include_prediction_snapshot:
        prediction_result = predict_attack(payload.sample)

    try:
        result = submit_feedback(
            sample=payload.sample,
            expected_label=payload.expected_label,
            feedback_source=payload.feedback_source or current_user.get("username") or "analyst",
            notes=payload.notes,
            prediction_result=prediction_result,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {"user": current_user, "result": result}


@app.post("/model/retrain")
def retrain_model(
    payload: ModelRetrainRequest,
    current_user: dict = Depends(get_current_user),
):
    try:
        result = retrain_model_from_feedback(
            min_feedback_samples=payload.min_feedback_samples,
            triggered_by=f"api:{current_user.get('username', 'unknown')}",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {"user": current_user, "result": result}


@app.post("/auth/login")
def login(payload: LoginRequest):
    user = authenticate_user(payload.username, payload.password)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    return {
        "access_token": create_access_token(user["username"]),
        "token_type": "bearer",
        "user": user,
    }


@app.post("/predict")
def protected_predict(
    payload: PredictionRequest,
    current_user: dict = Depends(get_current_user),
):
    request_payload = payload.model_dump()
    auto_remediate = request_payload.pop("auto_remediate", False)
    result = predict_attack(request_payload, auto_remediate=auto_remediate)
    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])

    return {"user": current_user, "result": result}


@app.post("/threat-intel/check")
def threat_intel_check(
    payload: ThreatIntelRequest,
    current_user: dict = Depends(get_current_user),
):
    intel = enrich_threat_intelligence(payload.model_dump())
    return {"user": current_user, "result": intel}


@app.get("/blacklist")
def get_blacklist(current_user: dict = Depends(get_current_user)):
    return {"user": current_user, "result": load_blacklist_db()}


@app.post("/blacklist")
def create_blacklist_entry(
    payload: BlacklistRequest,
    current_user: dict = Depends(get_current_user),
):
    try:
        entry = add_to_blacklist(
            payload.indicator_type,
            payload.value,
            payload.source,
            payload.reason,
            metadata={"created_by": current_user.get("username")},
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {"user": current_user, "result": entry}


@app.post("/vulnerability/scan")
def run_vulnerability_scan(
    payload: VulnerabilityScanRequest,
    current_user: dict = Depends(get_current_user),
):
    try:
        result = scan_target(payload.target, ports=payload.ports, timeout=payload.timeout)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {"user": current_user, "result": result}


@app.post("/capture/replay")
def run_packet_capture_replay(
    payload: PacketCaptureRequest,
    current_user: dict = Depends(get_current_user),
):
    try:
        result = run_dataset_packet_capture(
            packet_count=payload.packet_count,
            interval_seconds=payload.interval_seconds,
            attack_only=payload.attack_only,
            auto_remediate=payload.auto_remediate,
        )
    except (RuntimeError, ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {"user": current_user, "result": result}


@app.get("/forensics/history")
def get_forensics_history(current_user: dict = Depends(get_current_user)):
    return {"user": current_user, "result": load_attack_history()}


@app.get("/forensics/analysis")
def get_forensics_analysis(current_user: dict = Depends(get_current_user)):
    events = load_attack_history().get("events", [])
    return {"user": current_user, "result": analyze_attack_history(events)}


@app.get("/alerts/recent")
def get_alerts_recent(
    limit: int = 20,
    current_user: dict = Depends(get_current_user),
):
    return {"user": current_user, "result": get_recent_alerts(limit=limit)}


@app.get("/alerts/dashboard")
def get_alerts_dashboard(
    limit: int = 100,
    current_user: dict = Depends(get_current_user),
):
    return {"user": current_user, "result": get_alert_dashboard_snapshot(limit=limit)}


@app.get("/alerts/store")
def get_alerts_store(current_user: dict = Depends(get_current_user)):
    return {"user": current_user, "result": load_alert_store()}


@app.get("/forensics/export/csv")
def export_forensics_csv(current_user: dict = Depends(get_current_user)):
    _ = current_user
    payload = export_attack_history_csv(load_attack_history().get("events", []))
    headers = {"Content-Disposition": 'attachment; filename="cybershield_attack_history.csv"'}
    return Response(content=payload, media_type="text/csv", headers=headers)


@app.get("/forensics/export/pdf")
def export_forensics_pdf(current_user: dict = Depends(get_current_user)):
    _ = current_user
    try:
        payload = export_attack_history_pdf(load_attack_history().get("events", []))
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    headers = {"Content-Disposition": 'attachment; filename="cybershield_forensics_report.pdf"'}
    return Response(content=payload, media_type="application/pdf", headers=headers)
