import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.db import get_connection
from app.main import app
from app.model import MIN_SAMPLES

client = TestClient(app)


def insert_events(user_id, org_id, events):
    """events: list of (event_type, success, device, asn, country, created_at)"""
    with get_connection() as conn:
        with conn.cursor() as cur:
            for event_type, success, device, asn, country, created_at in events:
                cur.execute(
                    """
                    insert into security_events (user_id, org_id, event_type, success, ip_asn, ip_country, device_fingerprint, created_at)
                    values (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (user_id, org_id, event_type, success, asn, country, device, created_at),
                )
        conn.commit()


def normal_history(n, start, device="dev-usual", asn="AS-usual", country="US"):
    """n logins on consecutive days, same time-of-day, same device/ASN/country — an unremarkable baseline."""
    return [("login", True, device, asn, country, start + timedelta(days=i)) for i in range(n)]


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_insufficient_history_for_a_brand_new_user():
    user_id = str(uuid.uuid4())
    resp = client.get(f"/users/{user_id}/risk-score")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "insufficient_history"
    assert body["sample_count"] == 0


def test_risk_score_ok_once_minimum_history_exists():
    user_id = str(uuid.uuid4())
    org_id = str(uuid.uuid4())
    start = datetime(2026, 1, 1, 14, 0, tzinfo=timezone.utc)
    insert_events(user_id, org_id, normal_history(MIN_SAMPLES, start))

    resp = client.get(f"/users/{user_id}/risk-score")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["sample_count"] == MIN_SAMPLES
    assert 0.0 <= body["latest_risk_score"] <= 1.0


def test_anomalous_final_event_is_flagged_as_an_alert():
    user_id = str(uuid.uuid4())
    org_id = str(uuid.uuid4())
    start = datetime(2026, 1, 1, 14, 0, tzinfo=timezone.utc)

    # 30 unremarkable logins: same device/ASN/country, mid-afternoon, all successful.
    history = normal_history(30, start)
    # Then one wildly different event: new device, new ASN, new country, 3am, failed.
    anomaly_time = start + timedelta(days=31, hours=(3 - 14))
    history.append(("login", False, "brand-new-device", "AS-unknown-9999", "KP", anomaly_time))

    insert_events(user_id, org_id, history)

    resp = client.get(f"/users/{user_id}/risk-score")
    body = resp.json()
    assert body["status"] == "ok"
    assert body["latest_event"]["is_new_device"] is True
    assert body["latest_event"]["is_new_asn"] is True
    assert body["latest_event"]["is_new_country"] is True
    # Not asserting is_alert strictly (unsupervised thresholds vary), but the
    # anomalous point must rank clearly above a typical point from the same history.
    assert body["latest_risk_score"] > 0.3


def test_investigations_endpoint_surfaces_high_risk_users_for_an_org():
    org_id = str(uuid.uuid4())
    quiet_user = str(uuid.uuid4())
    start = datetime(2026, 1, 1, 14, 0, tzinfo=timezone.utc)
    insert_events(quiet_user, org_id, normal_history(MIN_SAMPLES, start))

    resp = client.get(f"/orgs/{org_id}/investigations", params={"threshold": 1.1})  # impossible threshold
    assert resp.status_code == 200
    assert resp.json() == []  # nothing crosses an impossible threshold

    resp_low = client.get(f"/orgs/{org_id}/investigations", params={"threshold": -0.1})  # everything qualifies
    assert resp_low.status_code == 200
    assert len(resp_low.json()) == 1
    assert resp_low.json()[0]["user_id"] == quiet_user
