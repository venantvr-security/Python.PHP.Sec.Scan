# db/cli.py
"""Database management CLI."""
import sys

from db.connection import init_db, drop_db, engine, DATABASE_URL


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m db.cli [init|drop|info]")
        sys.exit(1)

    command = sys.argv[1]

    if command == "init":
        print("Initializing database...")
        init_db()
        print("Database initialized successfully!")

    elif command == "drop":
        confirm = input("Are you sure you want to drop all tables? (yes/no): ")
        if confirm.lower() == "yes":
            drop_db()
            print("All tables dropped!")
        else:
            print("Cancelled.")

    elif command == "info":
        print(f"Database URL: {DATABASE_URL}")
        print(f"Engine: {engine}")
        print(f"Dialect: {engine.dialect.name}")

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
