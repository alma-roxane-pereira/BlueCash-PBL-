"""
Fixtures for the differential harness.

A fresh server pair per module: both accumulate audit leaves and spent tokens,
so sharing one pair across modules would make assertions order-dependent.
"""

from __future__ import annotations

import pytest

from . import keys as shared_keys
from . import servers
from .client import Device, Pair
from .compare import CredentialAliases, assert_json_equal


@pytest.fixture(scope="module")
def key_set() -> shared_keys.SharedKeys:
    """One test-only key set, shared by both servers for this module."""
    return shared_keys.generate()


@pytest.fixture(scope="module")
def server_pair(key_set, tmp_path_factory):
    """Start both servers on the shared keys, and always stop them.

    Teardown runs through `finally`, so a failure during startup or a crash
    mid-suite still leaves no orphaned process.
    """
    root = tmp_path_factory.mktemp("differential")
    logs = root / "logs"
    logs.mkdir()

    keys_file = key_set.write_reference_file(root / "reference_keys.json")
    database_url = f"sqlite:///{(root / 'backend.db').as_posix()}"
    shared_keys.seed_backend_database(database_url, key_set)

    reference = backend = None
    try:
        reference = servers.start_reference(keys_file, logs)
        backend = servers.start_backend(database_url, logs)
        yield reference, backend
    finally:
        for server in (backend, reference):
            if server is not None:
                server.stop()
        servers.assert_repo_is_clean_of_server_artefacts()


@pytest.fixture(scope="module")
def pair(server_pair):
    """HTTP clients for both servers, closed on teardown."""
    import httpx

    reference, backend = server_pair
    with httpx.Client(base_url=reference.base_url, timeout=30.0) as ref_client:
        with httpx.Client(base_url=backend.base_url, timeout=30.0) as be_client:
            yield Pair(reference=ref_client, backend=be_client)


@pytest.fixture(scope="module", autouse=True)
def _both_servers_loaded_the_same_keys(pair, key_set):
    """Guard: if the two servers are not on the same keys, every cryptographic
    comparison below is meaningless. Fail loudly before any protocol test runs.
    """
    ref, be = pair.get("/mint/keys")
    assert ref.status_code == 200, ref.text
    assert be.status_code == 200, be.text

    ref_body, be_body = ref.json(), be.json()
    assert ref_body["mint_pub"] == key_set.mint_pub_hex, (
        "the reference server did not load the shared key file"
    )
    assert be_body["mint_pub"] == key_set.mint_pub_hex, (
        "the backend did not load the seeded mint identity"
    )
    assert_json_equal(ref_body, be_body, "shared key set")


@pytest.fixture(scope="module")
def aliases() -> CredentialAliases:
    """Module-scoped, matching the servers.

    Settlement returns the *full* revocation list, so a response late in the
    module can contain credentials registered by an earlier test. A
    function-scoped alias table would not know those ids and would report a
    spurious mismatch.
    """
    return CredentialAliases()


@pytest.fixture
def device() -> Device:
    return Device()


def register(pair, aliases, device) -> tuple:
    """Register one device on both servers and alias the two credential ids.

    Returns the raw responses so a caller can assert on them.
    """
    body = device.register_body()
    ref, be = pair.post("/mint/registerDevice", body)
    if ref.status_code == 200 and be.status_code == 200:
        ref_cred = ref.json()["credential"]
        be_cred = be.json()["credential"]
        device.credentials["reference"] = ref_cred
        device.credentials["backend"] = be_cred
        aliases.pair(ref_cred["cred_id"], be_cred["cred_id"])
    return ref, be
