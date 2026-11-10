"""The runtime fixture must not touch arbitrary containers or bypass provenance."""
import importlib.util
import json
from pathlib import Path
from unittest.mock import patch
import pytest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('runtime_fixture',ROOT/'scripts/qualify_runtime.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def test_rejects_other_runtime_before_creating_any_fixture():
    with patch.object(m,'call',return_value=json.dumps([{'Config':{'Labels':{},'User':'0'},'Id':'other'}])) as call:
        with pytest.raises(ValueError):m.qualify('candidate')
        assert call.call_count==1


def test_failed_start_cleans_only_random_owned_postgres():
    calls=[]
    image={'Id':'sha256:'+'a'*64,'Config':{'User':'65532:65532','Labels':{
        'org.opencontainers.image.source':'https://github.com/hyperme-sh/api-keys-service',
        'org.opencontainers.image.revision':'b'*40}}}
    def execute(args,**kwargs):
        calls.append(args)
        if args[:3]==['docker','image','inspect']:return json.dumps([image])
        if 'run' in args:raise RuntimeError('fixture startup failed')
        if 'ps' in args:return 'owned-id'
        return ''
    with patch.object(m,'call',side_effect=execute):
        with pytest.raises(RuntimeError):m.qualify('candidate')
    start=next(a for a in calls if 'run' in a);name=start[start.index('--name')+1]
    assert name.startswith('api-keys-runtime-') and name.endswith('-postgres')
    assert start[start.index('--network')+1]=='none'
    assert '--publish' not in start and '--privileged' not in start
    assert ['docker','rm','--force','--volumes',name] in calls
    assert not any('prune' in a for a in calls)


def test_sigterm_unwinds_and_removes_owned_containers(tmp_path):
    """A real signal must unwind a detached fixture rather than exit abruptly."""
    import subprocess
    import sys
    program=r'''
import importlib.util,json,os,signal,sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('fixture',sys.argv[1])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
calls=[]
def call(args,**kwargs):
    calls.append(args)
    if args[:3]==['docker','image','inspect']:
        return json.dumps([{'Id':'local','Config':{'User':'65532:65532','Labels':{
            'org.opencontainers.image.source':'https://github.com/hyperme-sh/api-keys-service',
            'org.opencontainers.image.revision':'a'*40}}}])
    if 'run' in args and args[args.index('--name')+1].endswith('-app'):
        os.kill(os.getpid(),signal.SIGTERM)
    if 'ps' in args:return 'owned'
    return ''
try:
    with patch.object(m,'call',side_effect=call), patch.object(m.subprocess,'run',return_value=SimpleNamespace(returncode=0)):
        m.qualify('local',Path(sys.argv[2]))
finally:
    print(json.dumps(calls))
'''
    record=tmp_path/'owner'
    result=subprocess.run([sys.executable,'-c',program,str(ROOT/'scripts/qualify_runtime.py'),str(record)],
                          text=True,capture_output=True,timeout=10)
    assert result.returncode==143
    calls=json.loads(result.stdout)
    removed=[args[-1] for args in calls if args[:4]==['docker','rm','--force','--volumes']]
    assert len(removed)==3 and len({name.rsplit('-',1)[0] for name in removed})==1
    assert not record.exists()


def test_cleanup_attempts_every_owned_container_after_one_removal_fails():
    prefix='api-keys-runtime-'+'a'*32
    calls=[]
    def call(args,**kwargs):
        calls.append(args)
        if 'ps' in args:
            assert 'label=api-keys.qualifier.owner='+prefix in args
            return 'owned'
        if args[-1].endswith('-app'):raise RuntimeError('daemon refused')
        return ''
    with patch.object(m,'call',side_effect=call):
        with pytest.raises(RuntimeError,match='cleanup incomplete'):m.cleanup(prefix)
    assert [args[-1] for args in calls if 'rm' in args]==[
        prefix+'-app',prefix+'-bootstrap',prefix+'-postgres']


def test_recovery_rejects_arbitrary_owner_before_docker():
    with patch.object(m,'call') as call:
        with pytest.raises(ValueError):m.cleanup('someone-elses-database')
        call.assert_not_called()
