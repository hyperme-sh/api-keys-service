"""Static image-layer contracts; no Docker, network or service execution."""
import importlib.util
import io
import json
from pathlib import Path
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('runtime_layers', ROOT/'scripts/check_runtime_layers.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def tar(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as archive:
        for name, data in entries:
            item = tarfile.TarInfo(name)
            item.size = len(data)
            archive.addfile(item, io.BytesIO(data))
    return output.getvalue()


def image(tmp_path, layers):
    names = [f'{index}/layer.tar' for index in range(len(layers))]
    path = tmp_path/'image.tar'
    path.write_bytes(tar([('manifest.json', json.dumps([{'Layers': names}]).encode()),
                         *[(name, tar(entries)) for name, entries in zip(names, layers)]]))
    return path


def test_installed_runtime_and_licenses_are_allowed(tmp_path):
    m.check_archive(image(tmp_path, [[('opt/runtime/lib/python3.13/site-packages/api_keys_service/main.py', b'code'),
                                    ('usr/share/doc/python/copyright', b'license')]]))


@pytest.mark.parametrize('path', ['qualified/tested-dist.zip', './qualified/tested-dist.zip',
                                 '/qualified/tested-dist.zip', 'elsewhere/tested-dist.zip',
                                 'candidate/owner.whl', 'wheelhouse/dependency.whl'])
def test_owner_bundles_and_builder_inputs_are_refused(tmp_path, path):
    with pytest.raises(ValueError):
        m.check_archive(image(tmp_path, [[(path, b'archive')]]))


def test_later_whiteout_does_not_hide_retained_bundle(tmp_path):
    with pytest.raises(ValueError):
        m.check_archive(image(tmp_path, [[('qualified/tested-dist.zip', b'archive')],
                                        [('qualified/.wh.tested-dist.zip', b'')]]))


def test_parent_traversal_refuses_without_extracting(tmp_path):
    with pytest.raises(ValueError):
        m.check_archive(image(tmp_path, [[('../escape', b'bad')]]))
    assert not (tmp_path.parent/'escape').exists()


def test_missing_layer_and_empty_manifest_refuse(tmp_path):
    for manifest in ([], [{'Layers': ['missing/layer.tar']}], [{'Layers': []}]):
        path = tmp_path/'bad.tar'
        path.write_bytes(tar([('manifest.json', json.dumps(manifest).encode())]))
        with pytest.raises((ValueError, KeyError)):
            m.check_archive(path)
