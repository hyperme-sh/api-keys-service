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
import signal
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


def cleanup(prefix):
    if not re.fullmatch('api-keys-runtime-[a-f0-9]{32}', prefix):
        raise ValueError('Invalid fixture ownership record')
    errors=[]
    for suffix in ('app','bootstrap','postgres'):
        name=prefix+'-'+suffix
        try:
            if call(['docker','ps','-aq','--filter','name=^/'+name+'$',
                     '--filter','label=api-keys.qualifier.owner='+prefix]):
                call(['docker','rm','--force','--volumes',name])
        except Exception as error:errors.append(error)
    if errors:raise RuntimeError('Owned fixture cleanup incomplete') from None


def interrupted(signum, frame):
    raise SystemExit(128+signum)


def qualify(image, ownership_file=None):
    previous=signal.signal(signal.SIGTERM, interrupted)
    try:return _qualify(image, ownership_file)
    finally:signal.signal(signal.SIGTERM, previous)


def _qualify(image, ownership_file):
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
    if ownership_file is not None:
        # Names only, never credentials. Exclusive creation prevents replacing a
        # previous interrupted run's recovery record.
        with open(ownership_file, 'x', opener=lambda path, flags: os.open(path, flags, 0o600)) as record:
            record.write(prefix)
    try:
        call(['docker','run','--detach','--name',pg,'--label','api-keys.qualifier.owner='+prefix,'--network','none','--env','POSTGRES_PASSWORD','postgres:16-alpine'],env=environment)
        deadline=time.monotonic()+60
        while True:
            result=subprocess.run(['docker','exec',pg,'pg_isready','-h','127.0.0.1','-U','postgres'],capture_output=True,timeout=10)
            if result.returncode==0:break
            if time.monotonic()>deadline:raise RuntimeError('Owned PostgreSQL TCP readiness timed out')
            time.sleep(.2)
        bootstrap=['docker','run','--rm','--name',bootstrap_name,'--label','api-keys.qualifier.owner='+prefix,'--tmpfs','/tmp','--network','container:'+pg,'--read-only','--cap-drop','ALL',
                   '--security-opt','no-new-privileges:true','--entrypoint','python']
        for name in ('POSTGRES_PASSWORD','RUNTIME_DB_PASSWORD','FIXTURE_TENANT','FIXTURE_OTHER_TENANT'):
            bootstrap+=['--env',name]
        bootstrap+=['--mount','type=bind,src='+str(ROOT/'scripts/runtime/bootstrap.py')+',dst=/fixture.py,readonly',binary,'-I','/fixture.py']
        call(bootstrap,env=environment)
        command=['docker','run','--detach','--name',app,'--label','api-keys.qualifier.owner='+prefix,'--network','container:'+pg,
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
        cleanup(prefix)
        if ownership_file is not None:Path(ownership_file).unlink(missing_ok=True)
    if call(['docker','ps','-aq','--filter','label=api-keys.qualifier.owner='+prefix]):
        raise RuntimeError('Owned fixture cleanup incomplete')
    return {'image_id':binary,'source_sha':source['org.opencontainers.image.revision'],
            **observed,'fixture_cleanup_verified':True}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image')
    parser.add_argument('--ownership-file',type=Path)
    parser.add_argument('--cleanup',type=Path,metavar='OWNERSHIP_FILE')
    args=parser.parse_args()
    if args.cleanup:
        if args.image or args.ownership_file:parser.error('Cleanup is a separate operation')
        if args.cleanup.exists():
            cleanup(args.cleanup.read_text())
            args.cleanup.unlink()
    else:
        if not args.image:parser.error('--image is required')
        print(json.dumps(qualify(args.image,args.ownership_file),sort_keys=True))
