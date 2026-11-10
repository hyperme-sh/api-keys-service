"""Canonical keys bind a signed scope and current owner facts, not role labels."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
import uuid

from fastapi import HTTPException
import httpx
import pytest

from api_keys_service import authority, fingerprint, routes


@pytest.fixture
def scoped(monkeypatch,tmp_path):
    monkeypatch.setenv('API_KEYS_SCOPED_AUTHORITY_REQUIRED','1')
    monkeypatch.setenv('API_KEYS_USER_AUTHORITY_URL','https://owner.test')
    monkeypatch.setenv('API_KEYS_AUTHORITY_GENERATION','canonical-test')
    monkeypatch.setenv('API_KEYS_AUTHORITY_MANIFEST_SHA256','a'*64)
    key=tmp_path/'purpose-key';key.write_text('b'*64);key.chmod(0o600)
    monkeypatch.setenv('API_KEYS_AUTHORITY_TOKEN_FILE',str(key))
    fp=tmp_path/'fingerprint-key';fp.write_text('e'*64);fp.chmod(0o600)
    monkeypatch.setenv('API_KEYS_FINGERPRINT_TOKEN_FILE',str(fp))
    tenant,org=uuid.uuid4(),uuid.uuid4();subject=str(uuid.uuid4())
    selection=authority.Selection(tenant,org,'hyperme.sh','organization',subject,'canonical-test','a'*64)
    claims=dict(iss=authority.ISSUER,spanopticon_auth=authority.SPANOPTICON_AUTH,scope_version=1,
        tenant_id=str(tenant),organization_id=str(org),network_id='hyperme.sh',scope_kind='organization',
        sub=subject,scope_generation=selection.generation,scope_manifest_sha256=selection.manifest_sha256)
    return SimpleNamespace(selection=selection,claims=claims,tenant=tenant,org=org,subject=subject)


def install_transport(monkeypatch,handler):
    client=httpx.AsyncClient
    monkeypatch.setattr(authority.httpx,'AsyncClient',lambda **kwargs:client(transport=httpx.MockTransport(handler),**kwargs))


@pytest.mark.parametrize('change',[
    {'iss':'untrusted'},{'spanopticon_auth':'api_key'},{'scope_version':True},
    {'scope_version':None},{'scope_kind':'organization','organization_id':None},
    {'tenant_id':str(uuid.uuid4())},{'sub':'foreign-owner'},{'scope_manifest_sha256':'bad'},
    {'smoke_session':True},
])
def test_scoped_mode_rejects_unbound_forged_or_smoke_claims(scoped,change):
    with pytest.raises(HTTPException) as error:
        authority.selected({**scoped.claims,**change},scoped.tenant,scoped.subject)
    assert error.value.status_code==403


async def test_rpc_uses_purpose_credential_and_exact_verified_scope(scoped,monkeypatch):
    def handler(request):
        assert request.url.path=='/api/v1/internal/key-authority'
        assert request.headers['authorization']=='Bearer '+'b'*64
        assert request.headers['x-tenant-id']==str(scoped.tenant)
        body=json.loads(request.content)
        assert body['subject']==scoped.subject and body['organization_id']==str(scoped.org)
        return httpx.Response(200,json={**body,'allowed':True,'org_admin':False,'observed_at':datetime.now(UTC).isoformat()},headers={'Cache-Control':'no-store'})
    install_transport(monkeypatch,handler)
    selection=authority.selected(scoped.claims,scoped.tenant,scoped.subject)
    assert await authority.authorize(selection,'mint',purpose='renter')==selection


@pytest.mark.parametrize('fault',[
    'denied','redirect','unavailable','subject','tenant_id','organization_id','request_id',
    'manifest_sha256','allowed-string','admin-string','stale','future','cache','oversize',
])
async def test_authority_refuses_substitution_stale_or_unavailable_facts(scoped,monkeypatch,fault):
    def handler(request):
        body=json.loads(request.content)
        facts={**body,'allowed':True,'org_admin':False,'observed_at':datetime.now(UTC).isoformat()}
        if fault=='redirect':return httpx.Response(302,headers={'Location':'http://foreign.invalid/'})
        if fault=='unavailable':return httpx.Response(503)
        if fault=='oversize':return httpx.Response(200,content=b' '*17000,headers={'Cache-Control':'no-store'})
        if fault=='denied':facts['allowed']=False
        elif fault=='allowed-string':facts['allowed']='true'
        elif fault=='admin-string':facts['org_admin']='false'
        elif fault in ('stale','future'):
            facts['observed_at']=(datetime.now(UTC)+timedelta(minutes=-5 if fault=='stale' else 5)).isoformat()
        elif fault in body:facts[fault]='foreign'
        return httpx.Response(200,json=facts,headers={} if fault=='cache' else {'Cache-Control':'no-store'})
    install_transport(monkeypatch,handler)
    with pytest.raises(HTTPException) as error:await authority.authorize(scoped.selection,'use',purpose='renter')
    assert error.value.status_code==(403 if fault=='denied' else 503)


async def test_key_use_rechecks_current_membership_and_does_not_promote_enrollment_keys(scoped,monkeypatch):
    row=SimpleNamespace(id=uuid.uuid4(),tenant_id=scoped.tenant,created_by_sub=scoped.subject,purpose='renter',scopes=[])
    binding=dict(tenant_id=scoped.tenant,organization_id=scoped.org,network_id='hyperme.sh',scope_kind='organization',owner_sub=scoped.subject)
    monkeypatch.setattr(authority,'key_binding',AsyncMock(return_value=binding))
    verify=AsyncMock(return_value=scoped.selection);monkeypatch.setattr(authority,'authorize',verify)
    assert await authority.key_use(None,row)
    assert verify.call_args.kwargs==dict(purpose='renter',scopes=[])
    verify.side_effect=HTTPException(403,'membership removed')
    assert not await authority.key_use(None,row)
    monkeypatch.setattr(authority,'key_binding',AsyncMock(return_value=None));verify.reset_mock()
    assert not await authority.key_use(None,row)
    verify.assert_not_awaited()


async def test_org_admin_inventory_keeps_org_tenant_network_filters(scoped):
    calls=[]
    async def execute(statement,params):
        calls.append((str(statement),params))
        return SimpleNamespace(scalars=lambda:iter(()))
    session=SimpleNamespace(execute=execute)
    await authority.key_ids(session,replace(scoped.selection,org_admin=True))
    sql,params=calls.pop()
    assert all(term in sql for term in ('tenant_id=:tenant','network_id=:network','organization_id=:organization'))
    assert params['organization']==scoped.org and params['tenant']==scoped.tenant
    await authority.key_ids(session,scoped.selection)
    assert calls[-1][1]['subject']==scoped.subject and 'owner_sub=:subject' in calls[-1][0]


async def test_foreign_org_ir_mutation_is_hidden_even_from_another_org_admin(scoped,monkeypatch):
    row=SimpleNamespace(id=uuid.uuid4(),tenant_id=scoped.tenant,created_by_sub='foreign',purpose='ir',scopes=[])
    session=SimpleNamespace(execute=AsyncMock(return_value=SimpleNamespace(scalar_one_or_none=lambda:row)))
    user=SimpleNamespace(sub=scoped.subject,email='owner@example.invalid')
    monkeypatch.setattr(authority,'authorize',AsyncMock(return_value=replace(scoped.selection,org_admin=True)))
    monkeypatch.setattr(authority,'key_ids',AsyncMock(return_value=[]))
    old=AsyncMock();monkeypatch.setattr(routes,'actor_controls',old)
    with pytest.raises(HTTPException) as error:
        await routes._key_for_mutation(row.id,scoped.tenant,user,session,scoped.claims)
    assert error.value.status_code==404
    old.assert_not_awaited()


async def test_mint_rolls_back_when_required_fingerprint_owner_refuses(scoped,monkeypatch):
    selection=replace(scoped.selection,org_admin=True)
    monkeypatch.setattr(authority,'authorize',AsyncMock(return_value=selection))
    monkeypatch.setattr(authority,'bind',AsyncMock())
    monkeypatch.setattr(routes,'require_owner_open',AsyncMock())
    old=AsyncMock();monkeypatch.setattr(routes,'actor_controls',old)
    monkeypatch.setattr(routes,'publish_renter_key_fingerprint',AsyncMock(side_effect=fingerprint.FingerprintPublishError()))
    def refresh(row):row.id=uuid.uuid4();row.created_at=datetime.now(UTC)
    session=SimpleNamespace(add=lambda row:None,flush=AsyncMock(),refresh=AsyncMock(side_effect=refresh),rollback=AsyncMock())
    request=SimpleNamespace(state=SimpleNamespace(tenant_id=scoped.tenant),app=SimpleNamespace(state=SimpleNamespace()))
    with pytest.raises(HTTPException) as error:
        await routes.create_api_key(request,SimpleNamespace(sub=scoped.subject),routes.ApiKeyCreateRequest(purpose='renter'),
                                    scoped.tenant,session,scoped.claims)
    assert error.value.status_code==502
    session.rollback.assert_awaited_once();old.assert_not_awaited()
    assert authority.bind.call_args.args[2]==selection


@pytest.mark.parametrize('status',[199,200,201,204,299,300,302,400,500])
async def test_required_ir_fingerprint_acknowledgement_is_purpose_bound(scoped,monkeypatch,status):
    monkeypatch.setenv('HYPERMESH_CONTROL_PLANE_URL','https://plane.test')
    monkeypatch.setattr(fingerprint.settings,'hypermesh_internal_token','fixture-token')
    calls=[]
    def handler(request):calls.append(request.url.path);return httpx.Response(status)
    install_transport(monkeypatch,handler)
    if 200<=status<300:
        await fingerprint.publish_renter_key_fingerprint(scoped.tenant,'a'*64,purpose='ir',required=True)
    else:
        with pytest.raises(fingerprint.FingerprintPublishError):
            await fingerprint.publish_renter_key_fingerprint(scoped.tenant,'a'*64,purpose='ir',required=True)
    assert calls==['/api/v1/hypermesh/internal/ir-key-fingerprints']


async def test_touch_requires_verified_tenant_context(scoped,monkeypatch):
    monkeypatch.setattr(type(routes.settings),'usable_api_keys_internal_token',lambda self:'fixture')
    session=SimpleNamespace(execute=AsyncMock(),flush=AsyncMock())
    with pytest.raises(HTTPException) as error:
        await routes.internal_touch(routes.InternalTouchRequest(key_id=uuid.uuid4()),'fixture',session,None)
    assert error.value.status_code==400
    session.execute.assert_not_awaited();session.flush.assert_not_awaited()


@pytest.mark.parametrize('failed_owner',['user','plane','gateway'])
async def test_writer_activation_requires_protocol_capability_not_peer_build(scoped,monkeypatch,failed_owner):
    monkeypatch.setenv('HYPERMESH_CONTROL_PLANE_URL','https://plane.test')
    monkeypatch.setenv('API_KEYS_GATEWAY_URL','https://gateway.test')
    calls=[]
    def handler(request):
        calls.append(request.url.host)
        owner=request.url.host.split('.')[0]
        if owner==failed_owner:return httpx.Response(404)
        if owner=='owner':
            assert request.headers['authorization']=='Bearer '+'b'*64
            if failed_owner=='user':return httpx.Response(404)
            return httpx.Response(200,json={'api_key_authority_version':1,'additional_future_field':True})
        if owner=='plane':
            assert request.headers['x-internal-token']=='e'*64
            return httpx.Response(200,json={'api_key_registry_version':1})
        return httpx.Response(200,json={'api_key_scope_version':1,'require_key_scope':True})
    install_transport(monkeypatch,handler)
    engine=SimpleNamespace(connect=AsyncMock())
    with pytest.raises(RuntimeError):await authority.verify_runtime(engine)
    engine.connect.assert_not_called()


async def test_required_fingerprint_origin_accepts_one_trailing_slash(scoped,monkeypatch):
    monkeypatch.setenv('HYPERMESH_CONTROL_PLANE_URL','https://plane.test/')
    called=[]
    def handler(request):
        called.append(str(request.url));return httpx.Response(201,json={})
    install_transport(monkeypatch,handler)
    await fingerprint.publish_renter_key_fingerprint(scoped.tenant,'isolated.raw',required=True)
    assert called==['https://plane.test/api/v1/hypermesh/internal/renter-key-fingerprints']


@pytest.mark.parametrize('bound',[False,True])
async def test_network_revoke_acknowledges_pre_binding_fingerprint(scoped,monkeypatch,bound):
    row=SimpleNamespace(id=uuid.uuid4(),tenant_id=scoped.tenant,created_by_sub=scoped.subject,
        purpose='service',scopes=['oracles:attest'],key_fingerprint='c'*64,revoked_at=None)
    selection=replace(scoped.selection,organization_id=None,network_id='s3r.ch',scope_kind='network')
    claims={**scoped.claims,'organization_id':None,'network_id':'s3r.ch','scope_kind':'network'}
    monkeypatch.setattr(authority,'authorize',AsyncMock(return_value=selection))
    monkeypatch.setattr(authority,'key_ids',AsyncMock(return_value=[row.id]))
    monkeypatch.setattr(authority,'key_binding',AsyncMock(return_value={'key_id':row.id} if bound else None))
    revoke=AsyncMock(side_effect=fingerprint.FingerprintRevokeError())
    monkeypatch.setattr(routes,'revoke_renter_key_fingerprint',revoke)
    session=SimpleNamespace(execute=AsyncMock(return_value=SimpleNamespace(scalar_one_or_none=lambda:row)),flush=AsyncMock())
    user=SimpleNamespace(sub=scoped.subject,email='isolated@example.invalid')
    request=SimpleNamespace(state=SimpleNamespace(tenant_id=scoped.tenant),app=SimpleNamespace(state=SimpleNamespace()))
    if bound:
        await routes.revoke_api_key(row.id,request,user,scoped.tenant,session,claims)
        revoke.assert_not_awaited();assert row.revoked_at is not None
    else:
        with pytest.raises(HTTPException) as error:
            await routes.revoke_api_key(row.id,request,user,scoped.tenant,session,claims)
        assert error.value.status_code==502 and row.revoked_at is None
        revoke.side_effect=None
        await routes.revoke_api_key(row.id,request,user,scoped.tenant,session,claims)
        assert row.revoked_at is not None and revoke.await_count==2


async def test_gateway_capability_refuses_plaintext_before_contact(scoped,monkeypatch):
    monkeypatch.setenv('HYPERMESH_CONTROL_PLANE_URL','https://plane.test')
    monkeypatch.setenv('API_KEYS_GATEWAY_URL','http://gateway.test')
    calls=[]
    def handler(request):
        calls.append(request.url.host)
        return httpx.Response(200,json={'api_key_authority_version':1,'api_key_registry_version':1})
    install_transport(monkeypatch,handler)
    with pytest.raises(RuntimeError,match='Gateway scope HTTPS'):
        await authority.verify_runtime(SimpleNamespace(connect=AsyncMock()))
    assert calls==['owner.test','plane.test']
