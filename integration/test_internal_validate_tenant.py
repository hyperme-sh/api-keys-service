import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from api_keys_service.routes import internal_validate, settings
from api_keys_service.schemas import InternalValidateRequest


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
