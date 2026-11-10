"""Build a credential-free Docker context from tested bytes and verified wheels."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

from verify_dependency_fixtures import verify

ROOT=Path(__file__).resolve().parents[1]


def prepare(directory):
    if len(list(directory.glob('*.whl')))!=1 or len(list(directory.glob('*.tar.gz')))!=1:
        raise ValueError('Exactly one tested owner wheel and sdist required')
    dependencies=verify(ROOT)
    if (directory/'wheelhouse').exists():raise ValueError('Fresh runtime wheelhouse required')
    manifest=json.loads((ROOT/'tests_artifacts/dependencies/manifest.json').read_bytes())
    command=['uv','export','--frozen','--no-dev','--no-emit-project','--no-hashes']
    for item in manifest['dependencies']:command+=['--no-emit-package',item['distribution']]
    requirements=subprocess.check_output(command,cwd=ROOT,text=True)
    active=[line for line in requirements.splitlines() if line.strip() and not line.lstrip().startswith('#')]
    if any('git+' in line or ' @ ' in line for line in active):
        raise ValueError('Fixture runtime must not fetch Git or direct dependency references')
    target=directory/'requirements.txt';target.write_text(requirements)
    wheelhouse=directory/'wheelhouse';wheelhouse.mkdir()
    subprocess.run(['uv','run','--isolated','--no-project','--python','3.13','--with','pip',
                    'python','-m','pip','wheel','--no-deps','-r',str(target),'-w',str(wheelhouse)],check=True)
    for dependency in dependencies:shutil.copyfile(dependency,wheelhouse/dependency.name)
    with zipfile.ZipFile(directory/'tested-dist.zip','x') as archive:
        for path in sorted([*directory.glob('*.whl'),*directory.glob('*.tar.gz')]):archive.write(path,path.name)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directory',type=Path)
    args=parser.parse_args();prepare(args.directory.resolve())
