"""
Server process lifecycle for the differential harness.

Both servers are started on loopback only, with their state in a temporary
directory, and are always stopped -- including when a test fails or the harness
raises part-way through startup. Logs are captured and surfaced only when
something goes wrong.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = BACKEND_DIR.parent
REFERENCE_DIR = (
    REPO_ROOT / "bluecash-mobile-week1" / "bluecash-mobile" / "reference-server"
)

#: Generous: the backend opens a database and the reference parses a key file.
STARTUP_TIMEOUT_S = 25.0
POLL_INTERVAL_S = 0.15
#: Grace period between terminate() and kill().
SHUTDOWN_GRACE_S = 5.0


class ServerStartupError(RuntimeError):
    """A server did not become ready. Carries its captured log."""


def free_port() -> int:
    """Ask the OS for an unused loopback port.

    There is a small race between releasing the port and the server binding it.
    Acceptable here, and a bind failure surfaces as a startup error with the log
    attached rather than a mysterious hang.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@dataclass
class Server:
    """A running server process."""

    name: str
    port: int
    process: subprocess.Popen
    log_path: Path
    _log_handle: object = field(default=None, repr=False)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def log(self) -> str:
        try:
            return self.log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return "<log unavailable>"

    def is_running(self) -> bool:
        return self.process.poll() is None

    def stop(self) -> None:
        """Terminate, then kill if it will not go. Always closes the log."""
        try:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=SHUTDOWN_GRACE_S)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=SHUTDOWN_GRACE_S)
        finally:
            if self._log_handle is not None:
                try:
                    self._log_handle.close()
                except OSError:
                    pass


def _wait_until_ready(server: Server, probe_path: str) -> None:
    """Poll until the server answers, or fail with its log.

    The reference server has no `/health`, so readiness is probed with
    `/mint/keys`, which both expose.
    """
    deadline = time.monotonic() + STARTUP_TIMEOUT_S
    url = server.base_url + probe_path

    while time.monotonic() < deadline:
        if not server.is_running():
            raise ServerStartupError(
                f"{server.name} exited with code {server.process.returncode} "
                f"before becoming ready.\n--- log ---\n{server.log()}"
            )
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, OSError, TimeoutError):
            pass
        time.sleep(POLL_INTERVAL_S)

    raise ServerStartupError(
        f"{server.name} did not answer {url} within {STARTUP_TIMEOUT_S:.0f}s.\n"
        f"--- log ---\n{server.log()}"
    )


def _spawn(
    name: str, cwd: Path, env_extra: dict[str, str], port: int, log_dir: Path
) -> Server:
    import os

    env = os.environ.copy()
    env.update(env_extra)
    # Keep the harness's own settings from leaking into a child.
    env.pop("BLUECASH_STATE", None)

    log_path = log_dir / f"{name}.log"
    handle = log_path.open("w", encoding="utf-8")

    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "server:app" if name == "reference" else "app.main:app",
            "--host",
            "127.0.0.1",  # loopback only, never 0.0.0.0
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=str(cwd),
        env=env,
        stdout=handle,
        stderr=subprocess.STDOUT,
    )
    return Server(name=name, port=port, process=process, log_path=log_path, _log_handle=handle)


def start_reference(keys_file: Path, log_dir: Path) -> Server:
    """Start the reference server against a shared key file.

    `BLUECASH_KEYS` must always be set: unset, `_load_keys()` writes
    `mint_keys.json` into the working directory, which is inside the repository.

    `BLUECASH_STATE` is left unset so the reference keeps state in memory and
    starts clean -- it is never restarted mid-comparison, because it would lose
    that state while the backend would keep its own.
    """
    if not REFERENCE_DIR.exists():  # pragma: no cover - environment check
        raise ServerStartupError(f"reference server not found at {REFERENCE_DIR}")

    server = _spawn(
        "reference",
        cwd=REFERENCE_DIR,
        env_extra={"BLUECASH_KEYS": str(keys_file)},
        port=free_port(),
        log_dir=log_dir,
    )
    try:
        _wait_until_ready(server, "/mint/keys")
    except Exception:
        server.stop()
        raise
    return server


def start_backend(database_url: str, log_dir: Path) -> Server:
    """Start the backend against a seeded temporary database."""
    server = _spawn(
        "backend",
        cwd=BACKEND_DIR,
        env_extra={"BLUECASH_DATABASE_URL": database_url, "BLUECASH_ENV": "test"},
        port=free_port(),
        log_dir=log_dir,
    )
    try:
        _wait_until_ready(server, "/mint/keys")
    except Exception:
        server.stop()
        raise
    return server


def assert_repo_is_clean_of_server_artefacts() -> None:
    """No key or state file may have been written into the repository.

    The reference writes `mint_keys.json` into its working directory whenever
    `BLUECASH_KEYS` is unset, and that directory is inside the repo.
    """
    strays = []
    for name in ("mint_keys.json", "state.json"):
        for candidate in (REFERENCE_DIR / name, BACKEND_DIR / name, REPO_ROOT / name):
            if candidate.exists():
                strays.append(str(candidate))
    if (BACKEND_DIR / "bluecash.db").exists():
        strays.append(str(BACKEND_DIR / "bluecash.db"))
    if strays:  # pragma: no cover - only on a harness bug
        raise AssertionError(
            "server artefacts were written into the repository: " + ", ".join(strays)
        )
