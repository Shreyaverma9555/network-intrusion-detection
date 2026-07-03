from __future__ import annotations

from src.nid.logging_config import configure_logging
from src.nid.postgres import PostgresRepository


def main() -> None:
    logger = configure_logging("nid.backend.init", "app.log")
    repository = PostgresRepository()
    repository.initialize()
    health = repository.health()
    if not health.get("ready"):
        raise RuntimeError(
            "PostgreSQL schema initialization failed: "
            + ", ".join(health.get("missing_tables", []))
        )
    logger.info(
        "database_initialized tables=%s event_count=%s",
        ",".join(health["tables"]),
        health["event_count"],
    )


if __name__ == "__main__":
    main()
