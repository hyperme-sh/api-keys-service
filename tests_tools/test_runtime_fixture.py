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
