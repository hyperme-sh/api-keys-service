"""Purpose/ownership and fail-closed revocation through the actual route functions."""
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock
import uuid

import httpx
import pytest
from fastapi import HTTPException
from api.common.portal_controls import evaluate_portal_controls
from api.core.config import settings
from api_keys_service import fingerprint, routes


@pytest.fixture
def mutation(monkeypatch):
    tenant, key_id = uuid.uuid4(), uuid.uuid4()
    user = SimpleNamespace(sub='immutable-owner',email='changed@example.test',roles=['user'],groups=['ir'])
    row = SimpleNamespace(id=key_id,tenant_id=tenant,created_by_sub=user.sub,purpose='ir',
        name='original',key_prefix='prefix',scopes=[],created_at=datetime.now(UTC),
        revoked_at=None,last_used_at=None,key_fingerprint='a'*64)
    request = SimpleNamespace(state=SimpleNamespace(tenant_id=tenant),
                              app=SimpleNamespace(state=SimpleNamespace()))
    async def execute(statement):
        params=statement.compile().params
        # Enforce the real query's explicit ID AND tenant predicates, even
        # though this isolated route fixture does not depend on a live database.
        assert params['id_1']==key_id and params['tenant_id_1']==tenant
        match=row if row.id==key_id and row.tenant_id==tenant else None
        return SimpleNamespace(scalar_one_or_none=lambda:match)
    session=SimpleNamespace(execute=AsyncMock(side_effect=execute),flush=AsyncMock())
    async def controls(*args):return evaluate_portal_controls(user.roles,user.groups)
    monkeypatch.setattr(routes,'actor_controls',controls)
    monkeypatch.setattr(routes,'_mapped_lease',AsyncMock(return_value=None))
    revoker=AsyncMock()
    request.app.state.renter_key_fingerprint_revoker=revoker
    async def invoke(operation,claims=None):
        args=dict(key_id=key_id,request=request,user=user,_=tenant,session=session,claims=claims)
        if operation=='rename':args['body']=routes.ApiKeyRenameRequest(name='renamed')
        return await (routes.rename_api_key if operation=='rename' else routes.revoke_api_key)(**args)
    return SimpleNamespace(user=user,row=row,request=request,session=session,revoker=revoker,invoke=invoke)


@pytest.mark.asyncio
@pytest.mark.parametrize('operation',['rename','revoke'])
async def test_ir_only_actor_can_manage_own_ir_key_after_email_change(mutation,operation):
    assert not evaluate_portal_controls(mutation.user.roles,mutation.user.groups).can_mint_keys
    await mutation.invoke(operation)
    assert mutation.session.flush.await_count==1
    if operation=='rename':
        assert mutation.row.name=='renamed'
        mutation.revoker.assert_not_awaited()
    else:
        assert mutation.row.revoked_at is not None
        mutation.revoker.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize('operation',['rename','revoke'])
@pytest.mark.parametrize('foreign',['owner','tenant','missing-owner'])
async def test_ir_actor_cannot_mutate_foreign_or_unbound_key(mutation,operation,foreign):
    if foreign=='owner':mutation.row.created_by_sub='another-subject'
    elif foreign=='tenant':mutation.row.tenant_id=uuid.uuid4()
    else:mutation.row.created_by_sub=None
    with pytest.raises(HTTPException) as error:await mutation.invoke(operation)
    assert error.value.status_code==404
    assert mutation.row.name=='original' and mutation.row.revoked_at is None
    mutation.session.flush.assert_not_awaited();mutation.revoker.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('operation',['rename','revoke'])
@pytest.mark.parametrize('purpose,groups',[('renter',['ir']),('service',['ir']),('ir',['renter']),('ir',['billing']),('unknown',['renter'])])
async def test_key_purpose_requires_its_own_authority(mutation,operation,purpose,groups):
    mutation.row.purpose=purpose;mutation.user.groups=groups
    with pytest.raises(HTTPException) as error:await mutation.invoke(operation)
    assert error.value.status_code==403
    assert mutation.row.name=='original' and mutation.row.revoked_at is None
    mutation.session.flush.assert_not_awaited();mutation.revoker.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('operation',['rename','revoke'])
@pytest.mark.parametrize('purpose',['renter','service',None])
async def test_renter_and_service_mutation_authority_is_preserved(mutation,operation,purpose):
    mutation.row.purpose=purpose;mutation.user.groups=['renter']
    await mutation.invoke(operation)
    assert mutation.session.flush.await_count==1


@pytest.mark.asyncio
@pytest.mark.parametrize('operation',['rename','revoke'])
async def test_tenant_admin_can_manage_another_owners_ir_key(mutation,operation):
    mutation.user.roles=['admin'];mutation.user.groups=[];mutation.row.created_by_sub='other-subject'
    await mutation.invoke(operation)
    assert mutation.session.flush.await_count==1


@pytest.mark.asyncio
@pytest.mark.parametrize('operation',['rename','revoke'])
@pytest.mark.parametrize('foreign',[False,True])
async def test_smoke_restrictions_remain_in_force(mutation,operation,foreign):
    mutation.user.groups=['renter'];mutation.row.purpose='renter'
    if foreign:mutation.row.created_by_sub='another-subject'
    claims={'smoke_session':True,'sub':mutation.user.sub}
    if foreign:
        with pytest.raises(HTTPException) as error:await mutation.invoke(operation,claims)
        assert error.value.status_code==404
        mutation.session.flush.assert_not_awaited();mutation.revoker.assert_not_awaited()
    else:
        await mutation.invoke(operation,claims)
        assert mutation.session.flush.await_count==1


@pytest.mark.asyncio
@pytest.mark.parametrize('operation',['rename','revoke'])
async def test_smoke_session_cannot_manage_ir_keys_even_with_admin_role(mutation,operation):
    mutation.user.roles=['admin']
    with pytest.raises(HTTPException) as error:
        await mutation.invoke(operation,{'smoke_session':True,'sub':mutation.user.sub})
    assert error.value.status_code==403
    mutation.session.flush.assert_not_awaited();mutation.revoker.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('purpose,first_status,ir_status',[
    ('renter',200,None),('renter',204,None),('renter',299,None),
    ('renter',199,None),('renter',300,None),('renter',301,None),('renter',302,None),
    ('renter',303,None),('renter',307,None),('renter',308,None),('renter',401,None),('renter',503,None),
    ('ir',204,200),('ir',204,302),('ir',204,307),('ir',204,500),('ir',302,None),
])
async def test_local_revoke_waits_for_2xx_from_every_fingerprint_owner(mutation,monkeypatch,purpose,first_status,ir_status):
    mutation.row.purpose=purpose;mutation.user.roles=['admin']
    del mutation.request.app.state.renter_key_fingerprint_revoker
    monkeypatch.setenv('HYPERMESH_CONTROL_PLANE_URL','https://plane.example.test')
    monkeypatch.setattr(settings,'hypermesh_internal_token','synthetic-fixture-token')
    requests=[]
    def reply(request):
        requests.append(request)
        code=ir_status if request.url.path.endswith('/ir-key-fingerprints/revoke') else first_status
        return httpx.Response(code,headers={'Location':'https://redirect.example.test/never-follow'})
    original=httpx.AsyncClient
    monkeypatch.setattr(fingerprint.httpx,'AsyncClient',lambda **kwargs:original(transport=httpx.MockTransport(reply),**kwargs))
    accepted=200<=first_status<300 and (purpose!='ir' or (ir_status is not None and 200<=ir_status<300))
    if accepted:
        await mutation.invoke('revoke')
        assert mutation.row.revoked_at is not None
        mutation.session.flush.assert_awaited_once()
    else:
        with pytest.raises(HTTPException) as error:await mutation.invoke('revoke')
        assert error.value.status_code==502
        assert mutation.row.revoked_at is None
        mutation.session.flush.assert_not_awaited()
    assert len(requests)==(2 if purpose=='ir' and 200<=first_status<300 else 1)
    assert all(r.url.host=='plane.example.test' for r in requests)
    assert all(r.headers['X-Tenant-ID']==str(mutation.row.tenant_id) for r in requests)
