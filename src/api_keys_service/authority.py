"""Current User-owned authority and persistent key scope bindings.

Enabled by the deployment owner after schema qualification. No tenant-wide role
fallback, directory reads, synthetic sessions or authority caching in this mode.
"""
from dataclasses import dataclass, replace
from datetime import datetime, UTC
import json
import os
from pathlib import Path
import re
import stat
import ssl
from urllib.parse import urlsplit
import uuid

from fastapi import HTTPException
import httpx
from sqlalchemy import text

from controlplane_identity.security.tenant_session_jwt import ISSUER, SPANOPTICON_AUTH, is_smoke_session


def enabled():
    return os.environ.get('API_KEYS_SCOPED_AUTHORITY_REQUIRED')=='1'


@dataclass(frozen=True)
class Selection:
    tenant_id: uuid.UUID
    organization_id: uuid.UUID | None
    network_id: str
    scope_kind: str
    subject: str
    generation: str
    manifest_sha256: str
    org_admin: bool=False


def selected(claims,tenant_id,subject):
    try:
        if (not isinstance(claims,dict) or is_smoke_session(claims) or claims.get('iss')!=ISSUER
                or claims.get('spanopticon_auth')!=SPANOPTICON_AUTH
                or type(claims.get('scope_version')) is not int or claims['scope_version']!=1
                or claims.get('sub')!=subject or not subject or subject.startswith('apikey:')
                or uuid.UUID(claims['tenant_id'])!=tenant_id):raise ValueError()
        kind=claims['scope_kind'];org=claims.get('organization_id')
        if kind not in ('organization','network') or (kind=='organization')!=(org is not None):raise ValueError()
        network=claims['network_id'];generation=claims['scope_generation'];manifest=claims['scope_manifest_sha256']
        if (not isinstance(network,str) or not 1<=len(network)<=255
                or not isinstance(generation,str) or not 1<=len(generation)<=128
                or not isinstance(manifest,str) or not re.fullmatch('[a-f0-9]{64}',manifest)):raise ValueError()
        return Selection(tenant_id,uuid.UUID(org) if org is not None else None,network,kind,subject,generation,manifest)
    except (ValueError,TypeError,KeyError,AttributeError):
        raise HTTPException(403,'Current signed organization or network scope required') from None


def configured_selection(binding):
    try:
        return Selection(uuid.UUID(str(binding['tenant_id'])),
            uuid.UUID(str(binding['organization_id'])) if binding['organization_id'] is not None else None,
            binding['network_id'],binding['scope_kind'],binding['owner_sub'],
            os.environ['API_KEYS_AUTHORITY_GENERATION'],os.environ['API_KEYS_AUTHORITY_MANIFEST_SHA256'])
    except (ValueError,KeyError,TypeError):
        raise HTTPException(503,'Current key authority configuration unavailable') from None


def credential(variable="API_KEYS_AUTHORITY_TOKEN_FILE"):
    try:
        path=os.environ[variable]
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_mode&0o077 or info.st_uid not in (0,os.geteuid()):raise ValueError()
            with os.fdopen(fd,'r',closefd=False) as stream:secret=stream.read(65)
        finally:os.close(fd)
        if not re.fullmatch('[a-f0-9]{64}',secret):raise ValueError()
        return secret
    except (OSError,ValueError,KeyError,UnicodeError):
        raise HTTPException(503,'Key authority credential unavailable') from None


async def authorize(selection,operation,*,purpose=None,scopes=()):
    base=os.environ.get('API_KEYS_USER_AUTHORITY_URL','').rstrip('/')
    parsed=urlsplit(base)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment or parsed.path):
        raise HTTPException(503,'Key authority URL unavailable')
    body=dict(version=1,request_id=str(uuid.uuid4()),subject=selection.subject,
        tenant_id=str(selection.tenant_id),network_id=selection.network_id,
        organization_id=str(selection.organization_id) if selection.organization_id else None,
        scope_kind=selection.scope_kind,generation=selection.generation,
        manifest_sha256=selection.manifest_sha256,operation=operation,purpose=purpose,scopes=list(scopes))
    try:
        context=ssl.create_default_context(cafile=os.environ.get('API_KEYS_USER_AUTHORITY_CA_FILE') or None)
        async with httpx.AsyncClient(timeout=3,trust_env=False,follow_redirects=False,verify=context) as client:
            async with client.stream('POST',base+'/api/v1/internal/key-authority',
                headers={'Authorization':'Bearer '+credential(),'X-Tenant-ID':str(selection.tenant_id)},json=body) as response:
                if response.status_code==403:raise HTTPException(403,'Current key authority refused')
                if response.status_code!=200 or 'no-store' not in response.headers.get('Cache-Control',''):
                    raise ValueError()
                raw=bytearray()
                async for part in response.aiter_bytes():
                    raw.extend(part)
                    if len(raw)>16*1024:raise ValueError()
                facts=json.loads(raw)
        if (not isinstance(facts,dict) or type(facts.get('version')) is not int or any(facts.get(k)!=v for k,v in body.items())
                or type(facts.get('allowed')) is not bool or type(facts.get('org_admin')) is not bool):raise ValueError()
        observed=datetime.fromisoformat(facts['observed_at'])
        if observed.tzinfo is None or abs((datetime.now(UTC)-observed).total_seconds())>30:raise ValueError()
        if not facts['allowed']:raise HTTPException(403,'Current key authority refused')
        return replace(selection,org_admin=facts['org_admin'])
    except HTTPException:raise
    except (OSError,httpx.HTTPError,ValueError,KeyError,TypeError,OverflowError):
        raise HTTPException(503,'Current key authority unavailable') from None


async def key_ids(session,selection,key_id=None):
    conditions=['tenant_id=:tenant','network_id=:network','scope_kind=:kind']
    params=dict(tenant=selection.tenant_id,network=selection.network_id,kind=selection.scope_kind)
    if selection.organization_id is None:conditions.append('organization_id IS NULL')
    else:conditions.append('organization_id=:organization');params['organization']=selection.organization_id
    if not selection.org_admin or selection.scope_kind=='network':
        conditions.append('owner_sub=:subject');params['subject']=selection.subject
    if key_id is not None:conditions.append('key_id=:key');params['key']=key_id
    query='SELECT key_id FROM api_key_authority_bindings WHERE '+' AND '.join(conditions)
    # Retain revocation/listing for the exact pre-binding relay credentials
    # which key_use accepts. This cannot upgrade an enrollment/renter key.
    if (selection.scope_kind=='network' and selection.organization_id is None
            and selection.network_id=='s3r.ch'
            and str(selection.tenant_id)==os.environ.get('API_KEYS_ORACLES_TENANT_ID')):
        params['subject']=selection.subject
        query += " UNION SELECT id AS key_id FROM api_keys k WHERE tenant_id=:tenant AND created_by_sub=:subject AND purpose='service' AND scopes::jsonb='[\"oracles:attest\"]'::jsonb AND NOT EXISTS (SELECT FROM api_key_authority_bindings b WHERE b.key_id=k.id AND b.tenant_id=k.tenant_id)"
        if key_id is not None:query+=' AND id=:key'
    rows=await session.execute(text(query+' LIMIT 100001'),params)
    values=list(rows.scalars())
    if len(values)>100000:raise HTTPException(503,'Key inventory exceeds limit')
    return values


async def bind(session,row,selection):
    await session.execute(text('''INSERT INTO api_key_authority_bindings
        (key_id,tenant_id,organization_id,network_id,scope_kind,owner_sub,generation,manifest_sha256)
        VALUES(:key,:tenant,:organization,:network,:kind,:subject,:generation,:manifest)'''),
        dict(key=row.id,tenant=selection.tenant_id,organization=selection.organization_id,
            network=selection.network_id,kind=selection.scope_kind,subject=selection.subject,
            generation=selection.generation,manifest=selection.manifest_sha256))


async def key_binding(session,row):
    result=await session.execute(text('''SELECT * FROM api_key_authority_bindings
        WHERE key_id=:key AND tenant_id=:tenant AND owner_sub=:subject'''),
        {'key':row.id,'tenant':row.tenant_id,'subject':row.created_by_sub})
    return result.mappings().one_or_none()


async def key_use(session,row):
    if not row.created_by_sub:return False
    binding=await key_binding(session,row)
    if binding is None:
        # A configured network relay key can be verified against its current
        # owner without inventing an organization grant for enrollment keys.
        if (str(row.tenant_id)!=os.environ.get('API_KEYS_ORACLES_TENANT_ID')
                or row.purpose!='service' or row.scopes!=['oracles:attest']):return False
        binding=dict(tenant_id=row.tenant_id,organization_id=None,network_id='s3r.ch',
                     scope_kind='network',owner_sub=row.created_by_sub)
    selection=configured_selection(binding)
    try:await authorize(selection,'use',purpose=row.purpose,scopes=row.scopes or [])
    except HTTPException as error:
        if error.status_code==403:return False
        raise
    row._api_keys_organization_id=selection.organization_id
    row._api_keys_scope_kind=selection.scope_kind
    return True


async def verify_runtime(engine):
    if not enabled():return
    purpose_token=credential()
    if purpose_token==credential('API_KEYS_FINGERPRINT_TOKEN_FILE'):
        raise RuntimeError('Distinct owner-purpose credentials required')
    if (not os.environ.get('API_KEYS_USER_AUTHORITY_URL') or not os.environ.get('HYPERMESH_CONTROL_PLANE_URL')
            or not os.environ.get('API_KEYS_AUTHORITY_GENERATION')
            or not re.fullmatch('[a-f0-9]{64}',os.environ.get('API_KEYS_AUTHORITY_MANIFEST_SHA256',''))):
        raise RuntimeError('Complete scoped key-owner deployment required')
    owner=os.environ['API_KEYS_USER_AUTHORITY_URL'].rstrip('/')
    target=urlsplit(owner)
    if target.scheme!='https' or not target.hostname or target.username or target.password or target.path or target.query or target.fragment:
        raise RuntimeError('Verified User authority HTTPS origin required')
    try:
        context=ssl.create_default_context(cafile=os.environ.get('API_KEYS_USER_AUTHORITY_CA_FILE') or None)
        async with httpx.AsyncClient(timeout=3,trust_env=False,follow_redirects=False,verify=context) as client:
            response=await client.get(owner+'/api/v1/internal/key-authority/capabilities',headers={'Authorization':'Bearer '+purpose_token})
        if response.status_code!=200 or type(response.json().get('api_key_authority_version')) is not int or response.json().get('api_key_authority_version')!=1:
            raise ValueError()
    except (OSError,httpx.HTTPError,ValueError,AttributeError):
        raise RuntimeError('User key authority contract unavailable') from None
    fingerprint=os.environ['HYPERMESH_CONTROL_PLANE_URL'].rstrip('/')
    target=urlsplit(fingerprint)
    if target.scheme!='https' or not target.hostname or target.username or target.password or target.path or target.query or target.fragment:
        raise RuntimeError('Verified fingerprint owner HTTPS origin required')
    try:
        context=ssl.create_default_context(cafile=os.environ.get('API_KEYS_FINGERPRINT_CA_FILE') or None)
        async with httpx.AsyncClient(timeout=3,trust_env=False,follow_redirects=False,verify=context) as client:
            response=await client.get(fingerprint+'/api/v1/hypermesh/internal/key-registry-capabilities',
                headers={'X-Internal-Token':credential('API_KEYS_FINGERPRINT_TOKEN_FILE')})
        if response.status_code!=200 or type(response.json().get('api_key_registry_version')) is not int or response.json().get('api_key_registry_version')!=1:
            raise ValueError()
    except (OSError,httpx.HTTPError,ValueError,AttributeError):
        raise RuntimeError('Plane key registry contract unavailable') from None
    gateway=os.environ.get('API_KEYS_GATEWAY_URL','').rstrip('/')
    if not gateway:raise RuntimeError('Gateway scope contract URL required')
    try:
        async with httpx.AsyncClient(timeout=3,trust_env=False,follow_redirects=False) as client:
            response=await client.get(gateway+'/api/v1/hypermesh-gateway/key-scope-capabilities')
        if response.status_code!=200 or (type(response.json().get('api_key_scope_version')) is not int or response.json().get('api_key_scope_version')!=1 or response.json().get('require_key_scope') is not True):
            raise ValueError()
    except (httpx.HTTPError,ValueError,AttributeError):
        raise RuntimeError('Gateway organization key scope contract unavailable') from None
    async with engine.connect() as db:
        flags=(await db.execute(text('SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user'))).one()
        if any(flags):raise RuntimeError('Nonprivileged key runtime required')
        for name,privileges in {'api_keys':('SELECT','INSERT','UPDATE','DELETE'),
                'api_key_authority_bindings':('SELECT','INSERT'),
                'api_key_owner_closures':('SELECT','INSERT','UPDATE')}.items():
            flags=(await db.execute(text('SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid=to_regclass(:name)'),{'name':name})).one_or_none()
            if flags is None or not all(flags):raise RuntimeError('Forced tenant key-owner RLS required')
            for privilege in privileges:
                if not await db.scalar(text('SELECT has_table_privilege(current_user,:name,:privilege)'),{'name':name,'privilege':privilege}):
                    raise RuntimeError('Qualified permanent key-owner role required')
        if not await db.scalar(text("SELECT has_function_privilege(current_user,'api_key_subject_inventory(text)','EXECUTE')")):
            raise RuntimeError('Private key inventory contract required')
