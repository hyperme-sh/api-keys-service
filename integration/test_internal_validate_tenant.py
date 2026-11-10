import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from api_keys_service.routes import internal_validate, settings
from api_keys_service.schemas import InternalValidateRequest
from api_keys_service.crypto import hash_secret
from controlplane_db.models import ApiKey, Tenant
from api_keys_service import authority


async def test_edge_validation_sets_transaction_tenant(lifecycle_database, monkeypatch):
    tenant = uuid.uuid4()
    monkeypatch.setattr(type(settings), "usable_api_keys_internal_token", lambda self: "fixture-internal")
    engine = create_async_engine(lifecycle_database)
    try:
        async with async_sessionmaker(engine)() as session:
            body = InternalValidateRequest(api_key="absent.secret", tenant_id=tenant)
            result = await internal_validate(body, "fixture-internal", session)
            assert not result.valid
            assert await session.scalar(text("SELECT current_setting('app.current_tenant_id')")) == str(tenant)
    finally:
        await engine.dispose()


async def test_valid_edge_key_usage_persists_across_sessions(lifecycle_database, monkeypatch):
    tenant, key = uuid.uuid4(), uuid.uuid4()
    monkeypatch.setattr(type(settings), 'usable_api_keys_internal_token', lambda self: 'fixture-internal')
    monkeypatch.setattr(authority, 'enabled', lambda: False)
    engine = create_async_engine(lifecycle_database)
    sessions = async_sessionmaker(engine)
    try:
        async with sessions() as session:
            session.add(Tenant(id=tenant, name=str(tenant), is_active=True))
            await session.flush()
            session.add(ApiKey(id=key, tenant_id=tenant, key_prefix=key.hex[:16],
                               secret_hash=hash_secret('fixture-secret'), purpose='service',
                               scopes=['oracles:attest']))
            await session.commit()
        async with sessions() as session:
            result = await internal_validate(
                InternalValidateRequest(api_key=key.hex[:16]+'.fixture-secret', tenant_id=tenant),
                'fixture-internal', session,
            )
            assert result.valid
            await session.commit()
        async with sessions() as session:
            row = await session.get(ApiKey, key)
            assert row.last_used_at is not None
            assert row.revoked_at is None
    finally:
        await engine.dispose()
