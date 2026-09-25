from __future__ import annotations

import uuid

import pytest

from api_keys_service.fingerprint import (
    publish_renter_key_fingerprint,
    renter_key_fingerprint,
    revoke_renter_key_fingerprint,
)


def test_fingerprint_is_stable_hex_of_full_key():
    assert renter_key_fingerprint("pk_test.renter-key") == renter_key_fingerprint(
        "pk_test.renter-key"
    )
    assert renter_key_fingerprint("pk_test.renter-key") != renter_key_fingerprint(
        "pk_test.other"
    )
    assert len(renter_key_fingerprint("pk_test.renter-key")) == 64


@pytest.mark.asyncio
async def test_publish_calls_injected_hook():
    seen: list[tuple[uuid.UUID, str]] = []

    async def hook(tenant_id: uuid.UUID, fingerprint: str) -> None:
        seen.append((tenant_id, fingerprint))

    tid = uuid.uuid4()
    await publish_renter_key_fingerprint(
        tid, "a" * 64, publisher=hook
    )
    assert seen == [(tid, "a" * 64)]


@pytest.mark.asyncio
async def test_revoke_calls_injected_hook():
    seen: list[tuple[uuid.UUID, str]] = []

    async def hook(tenant_id: uuid.UUID, fingerprint: str) -> None:
        seen.append((tenant_id, fingerprint))

    tid = uuid.uuid4()
    await revoke_renter_key_fingerprint(tid, "c" * 64, publisher=hook)
    assert seen == [(tid, "c" * 64)]


@pytest.mark.asyncio
async def test_publish_is_noop_when_plane_url_unset(monkeypatch):
    monkeypatch.delenv("HYPERMESH_CONTROL_PLANE_URL", raising=False)
    await publish_renter_key_fingerprint(uuid.uuid4(), "b" * 64)
