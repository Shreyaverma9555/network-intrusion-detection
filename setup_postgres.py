from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path
from urllib.parse import quote

from dotenv import set_key
from psycopg import connect, sql


def main() -> None:
    parser = argparse.ArgumentParser(description="Configure PostgreSQL for the Network Intrusion Detection project.")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=5432)
    parser.add_argument("--admin-user", default="postgres")
    parser.add_argument("--database", default="nid")
    parser.add_argument("--app-user", default="nid_user")
    args = parser.parse_args()

    admin_password = getpass.getpass(f"PostgreSQL password for {args.admin_user}: ")
    app_password = getpass.getpass(f"New password for {args.app_user}: ")
    confirmation = getpass.getpass(f"Confirm password for {args.app_user}: ")
    if not app_password or app_password != confirmation:
        parser.error("Application passwords did not match or were empty.")

    try:
        with connect(
            host=args.host,
            port=args.port,
            dbname="postgres",
            user=args.admin_user,
            password=admin_password,
            autocommit=True,
        ) as connection:
            role_exists = connection.execute(
                "SELECT 1 FROM pg_roles WHERE rolname = %s", (args.app_user,)
            ).fetchone()
            if role_exists:
                connection.execute(
                    sql.SQL("ALTER ROLE {} WITH LOGIN PASSWORD {}").format(
                        sql.Identifier(args.app_user), sql.Literal(app_password)
                    )
                )
            else:
                connection.execute(
                    sql.SQL("CREATE ROLE {} WITH LOGIN PASSWORD {}").format(
                        sql.Identifier(args.app_user), sql.Literal(app_password)
                    )
                )

            database_exists = connection.execute(
                "SELECT 1 FROM pg_database WHERE datname = %s", (args.database,)
            ).fetchone()
            if not database_exists:
                connection.execute(
                    sql.SQL("CREATE DATABASE {} OWNER {}").format(
                        sql.Identifier(args.database), sql.Identifier(args.app_user)
                    )
                )

        dsn = (
            f"postgresql://{quote(args.app_user, safe='')}:{quote(app_password, safe='')}"
            f"@{args.host}:{args.port}/{quote(args.database, safe='')}"
        )
        env_path = Path(__file__).resolve().parent / ".env"
        set_key(str(env_path), "NID_POSTGRES_DSN", dsn)
        os.environ["NID_POSTGRES_DSN"] = dsn

        from src.nid.postgres import PostgresRepository

        PostgresRepository(dsn).initialize()
        print(f"PostgreSQL configured successfully: {args.database} / {args.app_user}")
        print("NID_POSTGRES_DSN was saved to .env and the SOC schema is ready.")
    except Exception as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
