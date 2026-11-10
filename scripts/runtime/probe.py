"""Exercise the actual runtime over loopback HTTP; print no keys or JWTs."""
import asyncio
import hashlib
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import os
from pathlib import Path
import threading
import time
import uuid

import httpx
from sqlalchemy import create_engine,text
from controlplane_api.config import settings
from controlplane_identity.configuration import configure_identity
from controlplane_identity.api_keys_client import validate_api_key_remote

configure_identity(settings)
from controlplane_identity.security.tenant_session_jwt import mint_tenant_session_jwt

TENANT=uuid.UUID(os.environ['FIXTURE_TENANT']);OTHER=uuid.UUID(os.environ['FIXTURE_OTHER_TENANT'])
OWNER=str(uuid.uuid4());FOREIGN=str(uuid.uuid4())
BASE='http://127.0.0.1:8000'
state={'revoke_status':204,'calls':[]};stage='runtime-role'


class Plane(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):
        self.send_response(404);self.end_headers()
    def do_POST(self):
        if self.headers.get('X-Internal-Token')!=os.environ['HYPERMESH_INTERNAL_TOKEN']:
            self.send_response(401);self.end_headers();return
        body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        assert self.headers.get('X-Tenant-ID')==str(TENANT)
        state['calls'].append((self.path,body['fingerprint']))
        status=state['revoke_status'] if self.path.endswith('/revoke') else 201
        self.send_response(status)
        if 300<=status<400:self.send_header('Location','http://127.0.0.1:1/never-follow')
        self.end_headers()


def token(subject=OWNER,tenant=TENANT,role='renter'):
    return mint_tenant_session_jwt(claims={'sub':subject,'email':'fixture@example.invalid'},
                                  tenant_id=tenant,extra_roles=[role])


def check():
    global stage
    assert os.geteuid()!=0
    engine=create_engine(os.environ['DATABASE_URL'].replace('postgresql+asyncpg://','postgresql+psycopg://'))
    with engine.connect() as connection:
        flags=connection.execute(text('SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user')).one()
        assert not any(flags)
    engine.dispose()
    plane=ThreadingHTTPServer(('127.0.0.1',18081),Plane)
    worker=threading.Thread(target=plane.serve_forever,daemon=True);worker.start()
    try:
        with httpx.Client(base_url=BASE,timeout=5,trust_env=False) as client:
            stage='health';deadline=time.monotonic()+60
            while True:
                try:
                    response=client.get('/api/v1/health/')
                    if response.status_code==200:break
                except httpx.HTTPError:pass
                if time.monotonic()>deadline:raise RuntimeError('Actual runtime did not become healthy')
                time.sleep(.2)
            assert response.json()=={'status':'Ok'}
            assert client.get('/version').status_code==200
            def headers(subject=OWNER,tenant=TENANT,role='renter'):
                return {'Authorization':'Bearer '+token(subject,tenant,role),'X-Tenant-ID':str(tenant)}
            def mint(purpose='renter'):
                response=client.post('/api/v1/api-keys',headers=headers(role='ir' if purpose=='ir' else 'renter'),
                                     json={'name':'isolated-runtime','purpose':purpose,'scopes':[]})
                state['failure_status']=response.status_code
                assert response.status_code==201,'Runtime mint refused'
                return response.json()
            stage='mint-renter';renter=mint();stage='mint-ir';ir=mint('ir')
            async def validate(key,tenant=TENANT):
                return await validate_api_key_remote(base_url=BASE,api_key=key,tenant_id=tenant)
            stage='rls-unscoped-visibility'
            with engine.connect() as connection:
                assert connection.scalar(text('SELECT count(*) FROM groups')) == 0
                stage='rls-owner-visibility'
                connection.execute(text("SELECT set_config('app.current_tenant_id', :tenant, true)"), {'tenant':str(TENANT)})
                assert connection.scalar(text('SELECT count(*) FROM groups')) == 1
                stage='rls-other-visibility'
                connection.execute(text("SELECT set_config('app.current_tenant_id', :tenant, true)"), {'tenant':str(OTHER)})
                assert connection.scalar(text('SELECT count(*) FROM groups')) == 1
                assert connection.scalar(text("SELECT count(*) FROM groups WHERE tenant_id=:tenant"),{'tenant':str(TENANT)}) == 0
                # Keys use explicit owner predicates; do not invent a fixture-only policy.
                assert connection.scalar(text("SELECT relrowsecurity FROM pg_class WHERE oid='api_keys'::regclass")) is False
            stage='sdk-validation' 
            assert asyncio.run(validate(renter['api_key']))['key_id']==renter['id']
            assert asyncio.run(validate(renter['api_key'],OTHER)) is None
            assert asyncio.run(validate('invalid.secret')) is None
            assert client.post('/api/v1/internal/validate',headers={'X-Internal-Token':'wrong'},
                               json={'api_key':renter['api_key'],'tenant_id':str(TENANT)}).status_code==401
            stage='tenant-touch'
            # The callback uses the tenant already established by key validation.
            assert client.post('/api/v1/internal/touch',headers={'X-Internal-Token':os.environ['API_KEYS_INTERNAL_TOKEN'],
                'X-Tenant-ID':str(TENANT)},json={'key_id':renter['id']}).status_code==204
            listed=client.get('/api/v1/api-keys',headers=headers()).json()
            assert next(r for r in listed if r['id']==renter['id'])['last_used_at'] is not None
            stage='ir-mutation';path='/api/v1/api-keys/'+ir['id']
            assert client.patch(path,headers=headers(role='ir'),json={'name':'renamed'}).status_code==200
            assert client.patch(path,headers=headers(subject=FOREIGN,role='ir'),json={'name':'foreign'}).status_code==404
            assert client.delete(path,headers=headers(tenant=OTHER,role='admin')).status_code==404
            mismatch=headers(tenant=OTHER,role='admin');mismatch['X-Tenant-ID']=str(TENANT)
            assert client.delete(path,headers=mismatch).status_code==403
            stage='fingerprint-revocation';state['revoke_status']=302
            assert client.delete(path,headers=headers(role='ir')).status_code==502
            assert asyncio.run(validate(ir['api_key'])) is not None
            state['revoke_status']=204
            assert client.delete(path,headers=headers(role='ir')).status_code==204
            assert asyncio.run(validate(ir['api_key'])) is None
            expected=hashlib.sha256(ir['api_key'].encode()).hexdigest()
            assert ('/api/v1/hypermesh/internal/ir-key-fingerprints/revoke',expected) in state['calls']
            assert ('/api/v1/hypermesh/internal/renter-key-fingerprints/revoke',expected) in state['calls']
        return {'actual_http':True,'runtime_non_superuser':True,'membership_rls_enforced':True,'api_keys_rls_enabled':False,
                'sdk_validation':True,'tenant_isolation':True,'purpose_ownership':True,
                'fingerprint_acknowledgement':True,'touch_with_tenant_context':True,'live_keys_used':False}
    finally:
        plane.shutdown();plane.server_close();worker.join(timeout=5)


if __name__=='__main__':
    try:print(json.dumps(check(),sort_keys=True))
    except Exception as error:
        import sys
        print(json.dumps({'failure_stage':stage,'exception_type':type(error).__name__,'http_status':state.get('failure_status')}),file=sys.stderr)
        raise SystemExit(1) from None
