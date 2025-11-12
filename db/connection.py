# db/connection.py
import os
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

from db.models import Base

# Database URL from environment or default to SQLite
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./scanner.db"  # Development default
)

# Production example: postgresql://user:password@localhost:5432/scanner_db

# Engine configuration
engine_kwargs = {
    "echo": os.getenv("SQL_ECHO", "false").lower() == "true",
}

# SQLite-specific optimizations
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs.update({
        "connect_args": {"check_same_thread": False},
        "poolclass": StaticPool,
    })


    # Enable foreign keys for SQLite
    @event.listens_for(Engine, "connect")
    def set_sqlite_pragma(dbapi_conn, connection_record):
        if DATABASE_URL.startswith("sqlite"):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")  # Better concurrency
            cursor.close()

# PostgreSQL-specific optimizations
elif DATABASE_URL.startswith("postgresql"):
    engine_kwargs.update({
        "pool_size": int(os.getenv("DB_POOL_SIZE", "10")),
        "max_overflow": int(os.getenv("DB_MAX_OVERFLOW", "20")),
        "pool_pre_ping": True,  # Verify connections before using
        "pool_recycle": 3600,  # Recycle connections after 1 hour
    })

# Create engine
engine = create_engine(DATABASE_URL, **engine_kwargs)

# Session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)


def init_db() -> None:
    """Initialize database schema (create all tables)."""
    Base.metadata.create_all(bind=engine)
    print(f"Database initialized: {DATABASE_URL}")


def drop_db() -> None:
    """Drop all tables (use with caution!)."""
    Base.metadata.drop_all(bind=engine)
    print("All tables dropped")


@contextmanager
def get_session() -> Generator[Session, None, None]:
    """
    Context manager for database sessions.

    Usage:
        with get_session() as session:
            project = session.query(Project).first()
    """
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Generator[Session, None, None]:
    """
    Dependency for FastAPI (yields session for dependency injection).

    Usage in FastAPI:
        @app.get("/projects")
        def get_projects(db: Session = Depends(get_db)):
            return db.query(Project).all()
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
