from __future__ import annotations

from typing import Tuple

import numpy as np

from sklearn.neighbors import NearestNeighbors


def smote_resample(
    X: np.ndarray,
    y: np.ndarray,
    *,
    k_neighbors: int = 5,
    random_state: int = 42,
) -> Tuple[np.ndarray, np.ndarray]:
    """Basic SMOTE implementation for numeric feature matrices.

    This is intentionally lightweight to keep the project stable on environments
    where `imbalanced-learn` is unavailable or version-incompatible.

    Args:
        X: Feature matrix of shape (n_samples, n_features)
        y: Binary label array of shape (n_samples,) with values {0,1}
        k_neighbors: Number of nearest neighbors to use for interpolation
        random_state: RNG seed

    Returns:
        (X_resampled, y_resampled)
    """

    X = np.asarray(X)
    y = np.asarray(y)

    if X.ndim != 2:
        raise ValueError("X must be 2D")
    if y.ndim != 1:
        raise ValueError("y must be 1D")
    if len(X) != len(y):
        raise ValueError("X and y must have the same length")

    classes, counts = np.unique(y, return_counts=True)
    if len(classes) != 2:
        return X, y

    maj_class = classes[int(np.argmax(counts))]
    min_class = classes[int(np.argmin(counts))]

    n_majority = int(np.max(counts))
    n_minority = int(np.min(counts))

    if n_minority == 0 or n_majority == n_minority:
        return X, y

    X_min = X[y == min_class]

    if len(X_min) < 2:
        return X, y

    rng = np.random.default_rng(int(random_state))

    k = int(max(1, min(k_neighbors, len(X_min) - 1)))
    nn = NearestNeighbors(n_neighbors=k + 1)
    nn.fit(X_min)

    # Cap synthetic generation to avoid excessive slowdowns on large, highly-imbalanced datasets.
    max_multiplier = 10
    target_minority = int(min(n_majority, n_minority * max_multiplier))
    n_to_generate = int(max(0, target_minority - n_minority))

    if n_to_generate <= 0:
        return X, y

    # Precompute neighbors once for all minority samples (exclude self at index 0).
    neigh = nn.kneighbors(X_min, return_distance=False)[:, 1:]

    idx = rng.integers(0, len(X_min), size=n_to_generate)
    neigh_pos = rng.integers(0, neigh.shape[1], size=n_to_generate)
    neigh_idx = neigh[idx, neigh_pos]

    x_i = X_min[idx]
    x_n = X_min[neigh_idx]
    alpha = rng.random(size=n_to_generate).reshape(-1, 1)
    synth = x_i + alpha * (x_n - x_i)

    X_res = np.vstack([X, synth])
    y_res = np.concatenate([y, np.full(n_to_generate, min_class, dtype=y.dtype)])

    return X_res, y_res
