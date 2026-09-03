import numpy as np
import pytest

from app.model import MIN_SAMPLES, score_events


def test_raises_below_minimum_sample_count():
    tiny = np.random.default_rng(0).normal(size=(MIN_SAMPLES - 1, 5))
    with pytest.raises(ValueError):
        score_events(tiny)


def test_scores_are_bounded_0_to_1():
    rng = np.random.default_rng(1)
    data = rng.normal(size=(50, 5))
    scores = score_events(data)
    assert scores.min() >= 0.0
    assert scores.max() <= 1.0


def test_an_injected_outlier_scores_higher_than_the_normal_cluster():
    rng = np.random.default_rng(2)
    normal_cluster = rng.normal(loc=0.0, scale=0.5, size=(49, 6))
    outlier = np.array([[50.0, 50.0, 50.0, 50.0, 50.0, 50.0]])  # far outside the cluster
    data = np.vstack([normal_cluster, outlier])

    scores = score_events(data)
    outlier_score = scores[-1]
    normal_scores = scores[:-1]

    assert outlier_score > normal_scores.mean() + 2 * normal_scores.std()
    assert outlier_score == scores.max()


def test_a_tight_uniform_cluster_produces_near_zero_scores_for_all_points():
    # All points identical -> no variance in anomaly scores -> should hit the
    # explicit hi-lo<epsilon branch and return all zeros, not NaN/inf.
    data = np.ones((20, 4))
    scores = score_events(data)
    assert np.all(scores == 0.0)
