"""
PhantomVault ML anomaly-detection service (docs/ARCHITECTURE.md §7/§8).

Consumes `security_events` written by the backend's telemetry pipeline
(src/security-events/emit.ts) and produces per-user risk scores for the
security/risk dashboard. Scores inform human-reviewable alerts; this
service never takes an autonomous enforcement action (THREAT_MODEL.md
§4.6 — an ML-triggered auto-lock would itself be an adversary-triggerable
DoS vector).
"""
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

from .db import get_connection
from .features import build_features, fetch_user_events
from .model import MIN_SAMPLES, score_events

app = FastAPI(title="PhantomVault ML Anomaly Detection Service")

RISK_ALERT_THRESHOLD = 0.7


class RiskScoreResponse(BaseModel):
    user_id: str
    status: str  # "ok" | "insufficient_history"
    sample_count: int
    latest_risk_score: float | None = None
    is_alert: bool = False
    latest_event: dict[str, Any] | None = None


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


def compute_risk_score(user_id: str) -> RiskScoreResponse:
    # psycopg returns uuid columns as uuid.UUID, not str — normalize here so
    # this function behaves the same whether called with a path-param string
    # (get_risk_score) or a value read straight back from the DB (get_org_investigations).
    user_id = str(user_id)
    with get_connection() as conn:
        events = fetch_user_events(conn, user_id)

    if len(events) < MIN_SAMPLES:
        return RiskScoreResponse(user_id=user_id, status="insufficient_history", sample_count=len(events))

    feature_matrix, flags = build_features(events)
    scores = score_events(feature_matrix)
    latest_score = float(scores[-1])

    return RiskScoreResponse(
        user_id=user_id,
        status="ok",
        sample_count=len(events),
        latest_risk_score=latest_score,
        is_alert=latest_score >= RISK_ALERT_THRESHOLD,
        latest_event=flags[-1],
    )


@app.get("/users/{user_id}/risk-score", response_model=RiskScoreResponse)
def get_risk_score(user_id: str) -> RiskScoreResponse:
    return compute_risk_score(user_id)


@app.get("/orgs/{org_id}/investigations")
def get_org_investigations(org_id: str, threshold: float = RISK_ALERT_THRESHOLD) -> list[RiskScoreResponse]:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "select distinct user_id from security_events where org_id = %s and user_id is not null",
                (org_id,),
            )
            user_ids = [r["user_id"] for r in cur.fetchall()]

    results = [compute_risk_score(uid) for uid in user_ids]
    alerting = [r for r in results if r.status == "ok" and r.latest_risk_score is not None and r.latest_risk_score >= threshold]
    alerting.sort(key=lambda r: r.latest_risk_score or 0.0, reverse=True)
    return alerting
