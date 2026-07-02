from __future__ import annotations

from pathlib import Path


def load_environment() -> bool:
    """Load project-local .env configuration without overriding shell variables."""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return False
    project_root = Path(__file__).resolve().parents[2]
    return bool(load_dotenv(project_root / ".env", override=False))
