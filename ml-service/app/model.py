"""
The actual ML: an IsolationForest (Liu, Ting & Zhou, 2008) — a real,
established unsupervised anomaly-detection algorithm from scikit-learn,
trained per-user on that user's own engineered behavioral features
(docs/ARCHITECTURE.md §7/§8). Not a heuristic threshold, not an LLM call.
"""
import numpy as np
from sklearn.ensemble import IsolationForest

# Below this many historical events, a per-user baseline is not
# statistically meaningful — the API reports "insufficient_history"
# rather than fabricating a score from too little data.
MIN_SAMPLES = 10


def score_events(feature_matrix: np.ndarray, random_state: int = 42) -> np.ndarray:
    """
    Returns a risk score per row in [0, 1], where higher = more anomalous
    relative to this user's own history. Raises if given fewer than
    MIN_SAMPLES rows — callers must check that before calling.
    """
    if feature_matrix.shape[0] < MIN_SAMPLES:
        raise ValueError(f"Need at least {MIN_SAMPLES} samples for a meaningful baseline, got {feature_matrix.shape[0]}")

    model = IsolationForest(n_estimators=200, contamination="auto", random_state=random_state)
    model.fit(feature_matrix)

    # score_samples: higher = more "normal" in IsolationForest's convention.
    # We invert and min-max normalize over this user's own score distribution
    # so the output is a comparable 0..1 risk value regardless of the raw
    # score's scale (which isn't meaningfully comparable across users/fits).
    raw = model.score_samples(feature_matrix)
    lo, hi = raw.min(), raw.max()
    if hi - lo < 1e-9:
        return np.zeros_like(raw)
    return 1.0 - (raw - lo) / (hi - lo)
