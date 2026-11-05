"""Database-backed key owner fencing and retry inventory; no other owner writes."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from api_keys_service.account_lifecycle import (
    CloseOwner,
    close_owner,
    require_owner_open,
)
from controlplane_db.models import ApiKey
from fastapi import HTTPException, Response
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


async def test_close_serializes_with_mint_and_inventory_survives_lost_reply(
    lifecycle_database, monkeypatch
):
    monkeypatch.setenv("ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED", "true")
    monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_TOKEN", "r" * 32)
    monkeypatch.setenv("ACCOUNT_CLOSURE_OPERATIONS_TOKEN", "w" * 32)
    tenant, other_tenant = uuid.uuid4(), uuid.uuid4()
    subject = str(uuid.uuid4())
    closed = datetime.now(UTC)
    permit_calls = []

    async def permit(**kwargs):
        permit_calls.append(kwargs)

    monkeypatch.setattr(
        "api_keys_service.account_lifecycle.require_closure_permit", permit
    )
    engine = create_async_engine(lifecycle_database)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker.begin() as session:
        for tid in (tenant, other_tenant):
            await session.execute(
                text(
                    "INSERT INTO tenants (id, name, is_active) VALUES (:id,:name,true)"
                ),
                {"id": tid, "name": str(tid)},
            )
        session.add(
            ApiKey(
                id=uuid.uuid4(),
                tenant_id=other_tenant,
                key_prefix=uuid.uuid4().hex[:16],
                secret_hash="not-real",
                name="other tenant",
                created_by_sub=subject,
                scopes=[],
                key_fingerprint="a" * 64,
            )
        )
        session.add(
            ApiKey(
                id=uuid.uuid4(),
                tenant_id=tenant,
                key_prefix=uuid.uuid4().hex[:16],
                secret_hash="not-real",
                name="other owner",
                created_by_sub="someone-else",
                scopes=[],
                key_fingerprint="b" * 64,
            )
        )
    ready, release = asyncio.Event(), asyncio.Event()
    created = uuid.uuid4()

    async def mint_before_close():
        async with maker.begin() as session:
            await require_owner_open(session, tenant, subject)
            ready.set()
            await release.wait()
            session.add(
                ApiKey(
                    id=created,
                    tenant_id=tenant,
                    key_prefix=uuid.uuid4().hex[:16],
                    secret_hash="not-real",
                    name="closing owner",
                    created_by_sub=subject,
                    scopes=[],
                    key_fingerprint="c" * 64,
                )
            )

    request = SimpleNamespace(
        state=SimpleNamespace(tenant_id=tenant),
        headers={"X-Account-Lifecycle-Token": "w" * 32},
    )

    async def revoke():
        async with maker.begin() as session:
            return await close_owner(
                request,
                Response(),
                CloseOwner(subject=subject, closed_at=closed),
                session,
            )

    try:
        mint_task = asyncio.create_task(mint_before_close())
        await asyncio.wait_for(ready.wait(), 5)
        close_task = asyncio.create_task(revoke())
        release.set()
        await mint_task
        inventory = await close_task
        assert inventory == {
            "keys": [{"id": str(created), "fingerprint": "c" * 64, "purpose": "renter"}]
        }
        assert await revoke() == inventory
        assert all(
            call == {"subject": subject, "closed_at": closed, "tenant_id": tenant}
            for call in permit_calls
        )
        async with maker.begin() as session:
            with pytest.raises(HTTPException) as error:
                await require_owner_open(session, tenant, subject)
            assert error.value.status_code == 403
            rows = (await session.execute(select(ApiKey))).scalars().all()
            assert all(
                (row.revoked_at == closed)
                if row.id == created
                else row.revoked_at is None
                for row in rows
            )
    finally:
        await engine.dispose()


async def test_mutation_needs_distinct_operations_credential(
    lifecycle_database, monkeypatch
):
    monkeypatch.setenv("ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED", "true")
    monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_TOKEN", "r" * 32)
    monkeypatch.setenv("ACCOUNT_CLOSURE_OPERATIONS_TOKEN", "w" * 32)
    for supplied in ("r" * 32, "wrong"):
        request = SimpleNamespace(headers={"X-Account-Lifecycle-Token": supplied})
        with pytest.raises(HTTPException) as error:
            await close_owner(
                request,
                Response(),
                CloseOwner(subject="person", closed_at=datetime.now(UTC)),
                None,
            )
        assert error.value.status_code == 403


async def test_inventory_without_membership_and_permitted_purge_preserve_other_owners(
    lifecycle_database, monkeypatch
):
    from datetime import timedelta

    from api_keys_service.account_lifecycle import owner_inventory, purge_owner

    monkeypatch.setenv("ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED", "true")
    monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_TOKEN", "r" * 32)
    monkeypatch.setenv("ACCOUNT_CLOSURE_OPERATIONS_TOKEN", "w" * 32)
    subject = str(uuid.uuid4())
    tenants = [uuid.uuid4(), uuid.uuid4()]
    identifiers = [uuid.uuid4() for _ in range(3)]
    closed = datetime.now(UTC) - timedelta(days=90)
    calls = []
    proof = {"keys": [], "keys_complete": True, "erasure_allowed": False}

    async def permit(**kwargs):
        calls.append(kwargs)

    async def scope(**kwargs):
        return proof

    monkeypatch.setattr(
        "api_keys_service.account_lifecycle.require_closure_permit", permit
    )
    monkeypatch.setattr("controlplane_identity.account_lifecycle.closure_scope", scope)
    engine = create_async_engine(lifecycle_database)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    body = CloseOwner(subject=subject, closed_at=closed)

    def request(tid):
        return SimpleNamespace(
            state=SimpleNamespace(tenant_id=tid),
            headers={"X-Account-Lifecycle-Token": "w" * 32},
        )

    try:
        async with maker.begin() as session:
            for tid in tenants:
                await session.execute(
                    text(
                        "INSERT INTO tenants (id,name,is_active) VALUES (:id,:name,true)"
                    ),
                    {"id": tid, "name": str(tid)},
                )
            for identifier, tid, owner in zip(
                identifiers,
                [tenants[0], tenants[1], tenants[0]],
                [subject, subject, "other-" + subject],
                strict=True,
            ):
                session.add(
                    ApiKey(
                        id=identifier,
                        tenant_id=tid,
                        created_by_sub=owner,
                        key_prefix=identifier.hex[:16],
                        secret_hash="not-real",
                        name="owned key",
                        scopes=[],
                        key_fingerprint=identifier.hex * 2,
                    )
                )
        async with maker.begin() as session:
            await session.execute(
                text("INSERT INTO identity_retirements VALUES (:s,:at)"),
                {"s": subject, "at": closed},
            )
            inventory = await owner_inventory(request(None), Response(), body, session)
            assert {key["tenant_id"] for key in inventory["keys"]} == {
                str(tid) for tid in tenants
            }
            assert {key["id"] for key in inventory["keys"]} == {
                str(value) for value in identifiers[:2]
            }
            assert calls[-1]["tenant_id"] is None
            receipt = await close_owner(request(tenants[0]), Response(), body, session)
            proof["keys"] = receipt["keys"]
        with pytest.raises(HTTPException, match="not yet authorized"):
            async with maker.begin() as session:
                await purge_owner(request(tenants[0]), Response(), body, session)
        proof["erasure_allowed"] = True
        proof["keys"] = []
        with pytest.raises(HTTPException, match="inventory does not match"):
            async with maker.begin() as session:
                await purge_owner(request(tenants[0]), Response(), body, session)
        proof["keys"] = receipt["keys"]
        for count in (1, 0):
            async with maker.begin() as session:
                result = await purge_owner(
                    request(tenants[0]), Response(), body, session
                )
                assert result == {"deleted": count, "remaining": 0}
        async with maker() as session:
            remaining = list(
                await session.scalars(select(ApiKey).where(ApiKey.id.in_(identifiers)))
            )
            assert {row.id for row in remaining} == set(identifiers[1:])
            assert all(row.revoked_at is None for row in remaining)
    finally:
        await engine.dispose()
