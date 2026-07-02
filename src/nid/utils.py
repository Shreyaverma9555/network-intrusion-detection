from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .paths import project_path


def read_json(path: str | Path) -> Any:
    with project_path(path).open("r", encoding="utf-8") as file:
        return json.load(file)


def write_json(path: str | Path, payload: Any) -> None:
    target = project_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2)
