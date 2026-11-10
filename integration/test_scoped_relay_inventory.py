"""Native key-owner query keeps accepted unbound relay credentials revocable."""
import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine,async_sessionmaker
from controlplane_db.models import Tenant,ApiKey
from api_keys_service import authority


async def test_exact_unbound_relay_inventory_uses_owner_tenant_and_scope(lifecycle_database,monkeypatch):
    engine=create_async_engine(lifecycle_database)
    tenant,foreign=uuid.uuid4(),uuid.uuid4();subject='isolated-'+uuid.uuid4().hex
    monkeypatch.setenv('API_KEYS_ORACLES_TENANT_ID',str(tenant))
    selection=authority.Selection(tenant,None,'s3r.ch','network',subject,'isolated','a'*64)
    try:
        async with async_sessionmaker(engine)() as db:
            # Only this native query's transaction uses an empty binding relation;
            # the actual User schema migration is qualified by its owner suite.
            await db.execute(text('CREATE TEMP TABLE api_key_authority_bindings(key_id uuid,tenant_id uuid,network_id text,scope_kind text,organization_id uuid,owner_sub text) ON COMMIT DROP'))
            db.add_all([Tenant(id=t,name=str(t),is_active=True) for t in (tenant,foreign)])
            await db.flush()
            accepted=uuid.uuid4()
            for key,tid,owner,purpose,scopes in [
                (accepted,tenant,subject,'service',['oracles:attest']),
                (uuid.uuid4(),foreign,subject,'service',['oracles:attest']),
                (uuid.uuid4(),tenant,'unrelated','service',['oracles:attest']),
                (uuid.uuid4(),tenant,subject,'renter',['oracles:attest']),
                (uuid.uuid4(),tenant,subject,'service',['unknown']),
            ]:
                db.add(ApiKey(id=key,tenant_id=tid,key_prefix=key.hex[:16],secret_hash='isolated-hash',key_fingerprint=key.hex*2,
                    created_by_sub=owner,purpose=purpose,scopes=scopes))
            await db.flush()
            assert await authority.key_ids(db,selection)==[accepted]
            assert await authority.key_ids(db,selection,accepted)==[accepted]
            assert await authority.key_ids(db,selection,uuid.uuid4())==[]
            assert await authority.key_ids(db,authority.Selection(tenant,uuid.uuid4(),'s3r.ch','organization',subject,'isolated','a'*64))==[]
            # Once a key has an explicit binding, the fallback never overrides it.
            await db.execute(text("INSERT INTO api_key_authority_bindings VALUES(:key,:tenant,'s3r.ch','organization',:org,:subject)"),
                {'key':accepted,'tenant':tenant,'org':uuid.uuid4(),'subject':subject})
            assert await authority.key_ids(db,selection)==[]
    finally:
        await engine.dispose()
