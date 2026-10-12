"""
Engine and session management.

Synchronous SQLAlchemy over the stdlib `sqlite3` driver. The mint's work is
short CPU-bound cryptography rather than long I/O waits, so async would add
machinery without buying throughput.

The engine is created lazily and cached, so importing this module does not open
a database. That keeps `GET /health` free of database dependencies, which the
health tests assert.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from ..config import Settings, get_settings
from .models import Base


def _is_sqlite(url: str) -> bool:
    return url.startswith("sqlite")


def create_db_engine(settings: Settings | None = None) -> Engine:
    """Build an engine for the configured database.

    SQLite needs two adjustments that PostgreSQL does not:

    * `check_same_thread=False`, because FastAPI serves requests from a
      threadpool and a session may be used on a different thread than it was
      created on;
    * `PRAGMA foreign_keys=ON` per connection, since SQLite ignores foreign
      keys by default — without it the `revocations -> devices` constraint
      would silently do nothing.
    """
    settings = settings or get_settings()
    url = settings.database_url

    kwargs: dict = {"echo": settings.database_echo, "future": True}
    if _is_sqlite(url):
        kwargs["connect_args"] = {"check_same_thread": False}

    engine = create_engine(url, **kwargs)

    if _is_sqlite(url):

        @event.listens_for(engine, "connect")
        def _sqlite_connect(dbapi_connection, _record):  # noqa: ANN001
            # SQLite ignores foreign keys unless asked, per connection. Without
            # this the revocations -> devices constraint silently does nothing.
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            # Wait for a competing writer instead of failing instantly with
            # "database is locked". Five seconds is far longer than any request
            # here should take.
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.close()

            # Hand transaction control to SQLAlchemy.
            #
            # pysqlite does not emit BEGIN on its own and commits implicitly
            # around DDL and SAVEPOINT. The effect is that a released SAVEPOINT
            # becomes durable immediately, so a later rollback of the enclosing
            # transaction cannot undo it -- a settlement batch that failed
            # halfway would leave the earlier receipts committed, crediting a
            # merchant for a batch the client was told had failed.
            #
            # Setting isolation_level = None disables pysqlite's own handling so
            # the "begin" hook below can issue BEGIN explicitly. This is
            # SQLAlchemy's documented recipe for serializable isolation and
            # working SAVEPOINTs on pysqlite.
            dbapi_connection.isolation_level = None

        @event.listens_for(engine, "begin")
        def _sqlite_begin(conn):  # noqa: ANN001
            # IMMEDIATE rather than plain BEGIN.
            #
            # A deferred transaction that reads first and writes later must
            # upgrade to a write lock. If another writer got there in between,
            # SQLite cannot resolve it by waiting -- both sides hold a read lock
            # -- so it fails at once with "database is locked", however long the
            # busy timeout is. Settlement and issuance both read-then-write, so
            # that case is the common one here, not an edge case.
            #
            # IMMEDIATE takes the write lock up front, so a competing writer
            # queues on the busy timeout instead. The cost is that transactions
            # serialise, which is the right trade for a prototype mint and is
            # specific to SQLite: PostgreSQL has real concurrent writers and
            # needs none of this.
            conn.exec_driver_sql("BEGIN IMMEDIATE")

    return engine


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    """The process-wide engine. Cached so connections are pooled."""
    return create_db_engine()


@lru_cache(maxsize=1)
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False, future=True)


def get_session() -> Iterator[Session]:
    """FastAPI dependency yielding a session, rolled back on error."""
    with get_sessionmaker()() as session:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise


@contextmanager
def session_scope(engine: Engine | None = None) -> Iterator[Session]:
    """A transactional session for scripts and tests."""
    factory = (
        sessionmaker(bind=engine, expire_on_commit=False, future=True)
        if engine is not None
        else get_sessionmaker()
    )
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def create_all(engine: Engine) -> None:
    """Create every table directly from the models.

    For tests and throwaway databases. A real database is built by Alembic, so
    that schema changes are versioned and reviewable — see `backend/README.md`.
    """
    Base.metadata.create_all(engine)


def drop_all(engine: Engine) -> None:
    """Drop every table. Tests only."""
    Base.metadata.drop_all(engine)


def reset_caches() -> None:
    """Clear the cached engine and sessionmaker.

    Tests that point the backend at a temporary database call this so the next
    access rebuilds against the new configuration.
    """
    get_engine.cache_clear()
    get_sessionmaker.cache_clear()
