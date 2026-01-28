from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib

from .training import TrainedBundle


def save_bundle(bundle: TrainedBundle, path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, p)


def load_bundle(path: str | Path) -> TrainedBundle:
    p = Path(path)
    obj: Any = joblib.load(p)
    if not isinstance(obj, TrainedBundle):
        raise TypeError(f"Expected TrainedBundle in artifact file, got: {type(obj)}")
    return obj
