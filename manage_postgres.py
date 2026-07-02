from __future__ import annotations

import argparse

from src.nid.postgres import PostgresRepository


def main() -> None:
    parser = argparse.ArgumentParser(description="Initialize and manage the NID PostgreSQL schema.")
    parser.add_argument("--init", action="store_true", help="Create event, user, and audit tables.")
    parser.add_argument("--user", help="Create or update an analyst username.")
    parser.add_argument("--role", choices=["admin", "analyst", "viewer"], default="analyst")
    parser.add_argument("--inactive", action="store_true", help="Mark the supplied user inactive.")
    args = parser.parse_args()
    if not args.init and not args.user:
        parser.error("Use --init and/or --user.")
    try:
        repository = PostgresRepository()
        if args.init:
            repository.initialize()
            print("PostgreSQL schema initialized.")
        if args.user:
            user_id = repository.upsert_user(args.user, args.role, active=not args.inactive)
            print(f"PostgreSQL user #{user_id} updated.")
    except Exception as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
