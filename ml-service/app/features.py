"""
Feature engineering for the anomaly-detection pipeline
(docs/ARCHITECTURE.md §7). Every input field here is one already
allow-listed into `security_events` by the backend — event type,
success/failure, coarse IP ASN/country, a device fingerprint hash,
and timestamp. Nothing here ever sees file contents, message plaintext,
or raw credentials.
"""
import math
from datetime import datetime
from typing import Any

import numpy as np

# Fixed, small vocabulary so the one-hot block has a stable width across
# calls. Unrecognized event types simply produce an all-zero block rather
# than growing the vocabulary at read time (which would make feature
# vectors from different calls incomparable).
EVENT_TYPES = [
    "login",
    "login_totp",
    "register",
    "device_registered",
    "capability_created",
    "capability_released",
    "capability_release_denied",
    "org_member_role_set",
    "totp_enabled",
]

FEATURE_NAMES = [
    "hour_sin", "hour_cos", "dow_sin", "dow_cos", "log_seconds_since_last_event",
    "is_new_device", "is_new_asn", "is_new_country", "success",
    *[f"event_type:{t}" for t in EVENT_TYPES],
]


def fetch_user_events(conn, user_id: str, limit: int = 500) -> list[dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(
            """
            select event_type, success, ip_asn, ip_country, device_fingerprint, created_at
            from security_events
            where user_id = %s
            order by created_at asc
            limit %s
            """,
            (user_id, limit),
        )
        return cur.fetchall()


def build_features(events: list[dict[str, Any]]) -> tuple[np.ndarray, list[dict[str, Any]]]:
    """
    Returns (feature_matrix, per_event_flags). `per_event_flags` carries the
    human-readable signals (new device/ASN/country, event type) used to
    explain a risk score on the dashboard, since IsolationForest itself
    doesn't give per-feature attribution without extra machinery
    (SHAP etc. — a documented enhancement, not implemented here).
    """
    seen_devices: set[str] = set()
    seen_asns: set[str] = set()
    seen_countries: set[str] = set()

    rows: list[list[float]] = []
    flags: list[dict[str, Any]] = []
    last_ts: datetime | None = None

    for e in events:
        ts: datetime = e["created_at"]
        hour = ts.hour + ts.minute / 60.0
        hour_sin = math.sin(2 * math.pi * hour / 24)
        hour_cos = math.cos(2 * math.pi * hour / 24)
        dow = ts.weekday()
        dow_sin = math.sin(2 * math.pi * dow / 7)
        dow_cos = math.cos(2 * math.pi * dow / 7)

        seconds_since_last = (ts - last_ts).total_seconds() if last_ts else 3600.0
        log_gap = math.log1p(max(seconds_since_last, 0.0))
        last_ts = ts

        device = e.get("device_fingerprint")
        asn = e.get("ip_asn")
        country = e.get("ip_country")

        is_new_device = 1.0 if device and device not in seen_devices else 0.0
        is_new_asn = 1.0 if asn and asn not in seen_asns else 0.0
        is_new_country = 1.0 if country and country not in seen_countries else 0.0

        if device:
            seen_devices.add(device)
        if asn:
            seen_asns.add(asn)
        if country:
            seen_countries.add(country)

        success = e.get("success")
        success_val = 1.0 if success is True else (0.0 if success is False else 0.5)

        event_type_onehot = [1.0 if e.get("event_type") == t else 0.0 for t in EVENT_TYPES]

        rows.append([
            hour_sin, hour_cos, dow_sin, dow_cos, log_gap,
            is_new_device, is_new_asn, is_new_country, success_val,
            *event_type_onehot,
        ])
        flags.append({
            "event_type": e.get("event_type"),
            "is_new_device": bool(is_new_device),
            "is_new_asn": bool(is_new_asn),
            "is_new_country": bool(is_new_country),
            "success": success,
            "created_at": ts.isoformat(),
        })

    return np.array(rows, dtype=float), flags
