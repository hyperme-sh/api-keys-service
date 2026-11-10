"""Own an isolated PostgreSQL/runtime fixture with no host ports or live inputs.

Both containers share the PostgreSQL container's network-none namespace. Only
loopback is available. Generated credentials stay in process environments;
cleanup removes only the two random fixture names and their anonymous volumes.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]


def call(args,*,env=None,timeout=180):
    result=subprocess.run(args,env=env,capture_output=True,text=True,timeout=timeout)
    if result.returncode:
        # Fixture diagnostics contain only exception types and code locations.
        lines=result.stderr.splitlines()
        try:
            failure=json.loads(lines[-1])
            detail=failure.get('exception_type','unknown')
            if not re.fullmatch('[A-Za-z]{1,64}',detail):detail='unknown'
            frames=failure.get('frames',[])
            locations=','.join(x for x in frames if re.fullmatch('[0-9]+:[A-Za-z_<>]{1,64}',x))
        except (ValueError,IndexError,AttributeError,TypeError):detail='unknown';locations=''
        raise RuntimeError('Isolated runtime command refused: '+detail+' '+locations)
    return result.stdout.strip()


def qualify(image):
    metadata=json.loads(call(['docker','image','inspect',image]))[0]
    source=metadata['Config'].get('Labels') or {}
    if (source.get('org.opencontainers.image.source')!='https://github.com/hyperme-sh/api-keys-service'
            or not re.fullmatch('[a-f0-9]{40}',source.get('org.opencontainers.image.revision',''))
            or metadata['Config'].get('User')!='65532:65532'):
        raise ValueError('Exact local standalone API keys runtime required')
    binary=metadata['Id'];prefix='api-keys-runtime-'+uuid.uuid4().hex
    pg,app,bootstrap_name=prefix+'-postgres',prefix+'-app',prefix+'-bootstrap'
    environment=dict(os.environ,POSTGRES_PASSWORD=uuid.uuid4().hex,RUNTIME_DB_PASSWORD=uuid.uuid4().hex,
        FIXTURE_TENANT=str(uuid.uuid4()),FIXTURE_OTHER_TENANT=str(uuid.uuid4()),
        API_KEYS_INTERNAL_TOKEN=uuid.uuid4().hex,HYPERMESH_INTERNAL_TOKEN=uuid.uuid4().hex,
        API_KEY_EXCHANGE_JWT_SECRET=uuid.uuid4().hex+uuid.uuid4().hex,
        HYPERMESH_CONTROL_PLANE_URL='http://127.0.0.1:18081',
        ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED='false',HOST='127.0.0.1',PORT='8000')
    environment['DATABASE_URL']='postgresql+asyncpg://api_keys_fixture_runtime:'+environment['RUNTIME_DB_PASSWORD']+'@127.0.0.1:5432/postgres'
    names=('DATABASE_URL','FIXTURE_TENANT','FIXTURE_OTHER_TENANT','API_KEYS_INTERNAL_TOKEN','HYPERMESH_INTERNAL_TOKEN',
           'API_KEY_EXCHANGE_JWT_SECRET','HYPERMESH_CONTROL_PLANE_URL','ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED','HOST','PORT')
    owned=[]
    try:
        owned.append(pg)
        call(['docker','run','--detach','--name',pg,'--network','none','--env','POSTGRES_PASSWORD','postgres:16-alpine'],env=environment)
        deadline=time.monotonic()+60
        while True:
            result=subprocess.run(['docker','exec',pg,'pg_isready','-h','127.0.0.1','-U','postgres'],capture_output=True,timeout=10)
            if result.returncode==0:break
            if time.monotonic()>deadline:raise RuntimeError('Owned PostgreSQL TCP readiness timed out')
            time.sleep(.2)
        owned.append(bootstrap_name)
        bootstrap=['docker','run','--rm','--name',bootstrap_name,'--tmpfs','/tmp','--network','container:'+pg,'--read-only','--cap-drop','ALL',
                   '--security-opt','no-new-privileges:true','--entrypoint','python']
        for name in ('POSTGRES_PASSWORD','RUNTIME_DB_PASSWORD','FIXTURE_TENANT','FIXTURE_OTHER_TENANT'):
            bootstrap+=['--env',name]
        bootstrap+=['--mount','type=bind,src='+str(ROOT/'scripts/runtime/bootstrap.py')+',dst=/fixture.py,readonly',binary,'-I','/fixture.py']
        call(bootstrap,env=environment)
        owned.append(app)
        command=['docker','run','--detach','--name',app,'--network','container:'+pg,
                 '--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--tmpfs','/tmp']
        for name in names:command+=['--env',name]
        call([*command,binary],env=environment)
        probe=['docker','exec']
        for name in names:probe+=['--env',name]
        # The fixture code is read on stdin rather than added to the product image.
        result=subprocess.run([*probe,'-i',app,'python','-I','-'],input=(ROOT/'scripts/runtime/probe.py').read_text(),
                              env=environment,capture_output=True,text=True,timeout=120)
        if result.returncode:
            # Only the probe's bounded stage identifier is safe to surface.
            try:
                failure=json.loads(result.stderr)
                stage=failure.get('failure_stage','unknown')
                status=failure.get('http_status')
            except (ValueError,AttributeError):stage='unknown';status=None
            if not re.fullmatch('[a-z-]{1,64}',stage):stage='unknown'
            raise RuntimeError('Isolated runtime HTTP contract refused at '+stage+' (HTTP '+str(status if isinstance(status,int) else 'unknown')+')')
        observed=json.loads(result.stdout)
    finally:
        for name in reversed(owned):
            if call(['docker','ps','-aq','--filter','name=^/'+name+'$']):
                call(['docker','rm','--force','--volumes',name])
    if call(['docker','ps','-aq','--filter','name=^/'+prefix+'-']):raise RuntimeError('Owned fixture cleanup incomplete')
    return {'image_id':binary,'source_sha':source['org.opencontainers.image.revision'],
            **observed,'fixture_cleanup_verified':True}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--image',required=True)
    args=parser.parse_args();print(json.dumps(qualify(args.image),sort_keys=True))
