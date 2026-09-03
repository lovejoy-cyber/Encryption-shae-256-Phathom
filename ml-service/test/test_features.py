from datetime import datetime, timedelta, timezone

from app.features import EVENT_TYPES, build_features


def make_event(dt, event_type="login", success=True, device="dev-1", asn="AS1", country="US"):
    return {
        "event_type": event_type,
        "success": success,
        "ip_asn": asn,
        "ip_country": country,
        "device_fingerprint": device,
        "created_at": dt,
    }


def test_feature_matrix_shape_matches_events_and_feature_count():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [make_event(base + timedelta(hours=i)) for i in range(5)]
    matrix, flags = build_features(events)
    assert matrix.shape[0] == 5
    assert matrix.shape[1] == 9 + len(EVENT_TYPES)  # 9 hand-crafted + one-hot block
    assert len(flags) == 5


def test_first_occurrence_of_a_device_is_flagged_new_subsequent_ones_are_not():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [
        make_event(base, device="dev-A"),
        make_event(base + timedelta(hours=1), device="dev-A"),
        make_event(base + timedelta(hours=2), device="dev-B"),
    ]
    _, flags = build_features(events)
    assert flags[0]["is_new_device"] is True
    assert flags[1]["is_new_device"] is False
    assert flags[2]["is_new_device"] is True  # dev-B never seen before


def test_new_asn_and_country_tracked_independently_of_device():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [
        make_event(base, device="dev-A", asn="AS100", country="US"),
        make_event(base + timedelta(hours=1), device="dev-A", asn="AS999", country="RU"),
    ]
    _, flags = build_features(events)
    assert flags[1]["is_new_device"] is False  # same device
    assert flags[1]["is_new_asn"] is True      # different ASN
    assert flags[1]["is_new_country"] is True  # different country


def test_success_encoding():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [
        make_event(base, success=True),
        make_event(base + timedelta(hours=1), success=False),
        make_event(base + timedelta(hours=2), success=None),
    ]
    matrix, _ = build_features(events)
    success_col = 8  # index within the hand-crafted feature block, see FEATURE_NAMES
    assert matrix[0, success_col] == 1.0
    assert matrix[1, success_col] == 0.0
    assert matrix[2, success_col] == 0.5


def test_time_gap_feature_is_larger_for_bursty_vs_spread_out_events():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    bursty = [make_event(base), make_event(base + timedelta(seconds=1))]
    spread = [make_event(base), make_event(base + timedelta(days=1))]
    bursty_matrix, _ = build_features(bursty)
    spread_matrix, _ = build_features(spread)
    gap_col = 4
    assert bursty_matrix[1, gap_col] < spread_matrix[1, gap_col]


def test_unrecognized_event_type_produces_all_zero_onehot_block_not_an_error():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [make_event(base, event_type="some_future_event_type_not_in_vocab")]
    matrix, _ = build_features(events)
    onehot_block = matrix[0, 9:]
    assert onehot_block.sum() == 0.0
