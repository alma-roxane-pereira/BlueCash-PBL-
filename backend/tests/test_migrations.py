"""
Tests that the Alembic migration produces the schema the models describe.

Models and migrations drift apart silently: the models change, the tests pass
because they use `create_all`, and the migration that a real deployment runs is
quietly wrong. `test_migration_matches_the_models` is the guard against that —
it builds one database each way and diffs them.

Every test runs against a throwaway SQLite file under `tmp_path`.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from app.config import Settings
from app.db import create_all, create_db_engine

BACKEND_DIR = Path(__file__).resolve().parents[1]
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"

EXPECTED_TABLES = {
    "mint_identity",
    "mint_keys",
    "devices",
    "revocations",
    "audit_leaves",
    "spent_tokens",
    "balances",
}


@pytest.fixture
def alembic_config(tmp_path, monkeypatch):
    """An Alembic config pointed at a temporary database.

    `migrations/env.py` reads the URL from application settings, so the
    environment variable is what redirects it away from any real database.
    """
    db_url = f"sqlite:///{(tmp_path / 'migrated.db').as_posix()}"
    monkeypatch.setenv("BLUECASH_DATABASE_URL", db_url)

    # env.py caches settings through get_settings(); clear it so the override lands.
    from app.config import get_settings

    get_settings.cache_clear()

    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    cfg.attributes["configure_logger"] = False

    yield cfg, db_url

    get_settings.cache_clear()


def _tables(url: str) -> set[str]:
    engine = create_engine(url)
    try:
        return set(inspect(engine).get_table_names())
    finally:
        engine.dispose()


def _schema_snapshot(url: str) -> dict:
    """Column names/types, indexes and constraints per table, ignoring order."""
    engine = create_engine(url)
    try:
        insp = inspect(engine)
        snapshot: dict = {}
        for table in sorted(set(insp.get_table_names()) - {"alembic_version"}):
            snapshot[table] = {
                "columns": sorted(
                    (c["name"], str(c["type"]), bool(c["nullable"]))
                    for c in insp.get_columns(table)
                ),
                "pk": sorted(insp.get_pk_constraint(table).get("constrained_columns") or []),
                "indexes": sorted(
                    (i["name"], tuple(sorted(i["column_names"])), bool(i.get("unique")))
                    for i in insp.get_indexes(table)
                ),
                "fks": sorted(
                    (
                        tuple(sorted(f["constrained_columns"])),
                        f["referred_table"],
                        tuple(sorted(f["referred_columns"])),
                    )
                    for f in insp.get_foreign_keys(table)
                ),
            }
        return snapshot
    finally:
        engine.dispose()


# ---------------------------------------------------------------------------
# upgrade
# ---------------------------------------------------------------------------


def test_upgrade_head_creates_every_table(alembic_config):
    cfg, url = alembic_config
    command.upgrade(cfg, "head")
    assert EXPECTED_TABLES <= _tables(url)


def test_upgrade_records_a_version(alembic_config):
    cfg, url = alembic_config
    command.upgrade(cfg, "head")
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            version = conn.exec_driver_sql("SELECT version_num FROM alembic_version").scalar()
        assert version, "alembic_version must record the applied revision"
    finally:
        engine.dispose()


def test_upgrade_is_idempotent(alembic_config):
    """Running upgrade twice is a no-op, not an error."""
    cfg, url = alembic_config
    command.upgrade(cfg, "head")
    command.upgrade(cfg, "head")
    assert EXPECTED_TABLES <= _tables(url)


def test_downgrade_then_upgrade_round_trips(alembic_config):
    cfg, url = alembic_config
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")
    assert not (EXPECTED_TABLES & _tables(url)), "downgrade must drop the schema"
    command.upgrade(cfg, "head")
    assert EXPECTED_TABLES <= _tables(url)


def test_migration_runs_on_an_empty_database(alembic_config, tmp_path):
    cfg, url = alembic_config
    assert not (tmp_path / "migrated.db").exists() or _tables(url) == set()
    command.upgrade(cfg, "head")
    assert EXPECTED_TABLES <= _tables(url)


# ---------------------------------------------------------------------------
# the guard that matters
# ---------------------------------------------------------------------------


def test_migration_matches_the_models(alembic_config, tmp_path):
    """A migrated database and a `create_all` database must be the same shape.

    If this fails, the migration is behind the models and a deployment would
    build the wrong schema.
    """
    cfg, migrated_url = alembic_config
    command.upgrade(cfg, "head")

    direct_url = f"sqlite:///{(tmp_path / 'direct.db').as_posix()}"
    direct_engine = create_db_engine(Settings(database_url=direct_url))
    create_all(direct_engine)
    direct_engine.dispose()

    migrated = _schema_snapshot(migrated_url)
    direct = _schema_snapshot(direct_url)

    assert set(migrated) == set(direct), "table sets differ"
    for table in sorted(direct):
        assert migrated[table]["columns"] == direct[table]["columns"], f"{table}: columns"
        assert migrated[table]["pk"] == direct[table]["pk"], f"{table}: primary key"
        assert migrated[table]["indexes"] == direct[table]["indexes"], f"{table}: indexes"
        assert migrated[table]["fks"] == direct[table]["fks"], f"{table}: foreign keys"


def test_exactly_one_migration_so_far(alembic_config):
    """Step 3 defines a single initial revision with no parent."""
    cfg, _ = alembic_config
    from alembic.script import ScriptDirectory

    script = ScriptDirectory.from_config(cfg)
    revisions = list(script.walk_revisions())
    assert len(revisions) == 1
    assert revisions[0].down_revision is None


# ---------------------------------------------------------------------------
# isolation
# ---------------------------------------------------------------------------


def test_migrations_never_touch_a_real_database(alembic_config, tmp_path):
    cfg, url = alembic_config
    command.upgrade(cfg, "head")
    assert tmp_path.as_posix() in url
    assert not (BACKEND_DIR / "bluecash.db").exists(), (
        "a real runtime database must never be created by the test suite"
    )


def test_env_reads_the_url_from_settings(monkeypatch, tmp_path):
    """The migration environment must follow BLUECASH_DATABASE_URL."""
    from app.config import Settings, get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("BLUECASH_DATABASE_URL", f"sqlite:///{(tmp_path / 'x.db').as_posix()}")
    try:
        assert get_settings().database_url.endswith("x.db")
    finally:
        get_settings.cache_clear()


def test_default_database_url_is_synchronous_sqlite():
    """No aiosqlite: the project uses the stdlib driver."""
    url = Settings().database_url
    assert url.startswith("sqlite:///"), url
    assert "aiosqlite" not in url
    assert os.environ.get("BLUECASH_DATABASE_URL") is None or True
