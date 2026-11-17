"""Refuse retained owner distribution bundles and builder inputs in image layers."""
import argparse
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile


def check_archive(path):
    # Inspect every layer, including files hidden by later whiteouts. Never extract
    # registry-controlled names onto the runner filesystem.
    with tarfile.open(path, 'r:*') as archive:
        member = archive.getmember('manifest.json')
        if not member.isfile() or member.size > 1024 * 1024:
            raise ValueError('Image manifest required')
        with archive.extractfile(member) as stream:
            manifest = json.load(stream)
        if not isinstance(manifest, list) or len(manifest) != 1:
            raise ValueError('One runtime image required')
        layers = manifest[0]['Layers']
        if not isinstance(layers, list) or not 1 <= len(layers) <= 128:
            raise ValueError('Bounded image layers required')
        for name in layers:
            if not isinstance(name, str):
                raise ValueError('Image layer required')
            layer = archive.getmember(name)
            if not layer.isfile():
                raise ValueError('Regular image layer required')
            with archive.extractfile(layer) as stream, tarfile.open(fileobj=stream, mode='r|*') as contents:
                for entry in contents:
                    parts = PurePosixPath(entry.name.lstrip('/')).parts
                    if '..' in parts:
                        raise ValueError('Invalid layer path')
                    if parts and (parts[0] in {'qualified', 'candidate', 'wheelhouse'}
                                  or parts[-1] == 'tested-dist.zip'):
                        raise ValueError('Runtime retains owner distribution or builder inputs')


def check_image(image):
    with tempfile.TemporaryDirectory(prefix='api-keys-layer-check-') as directory:
        path = Path(directory) / 'image.tar'
        subprocess.run(['docker', 'image', 'save', '--output', str(path), image],
                       check=True, capture_output=True, timeout=180)
        check_archive(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    args = parser.parse_args()
    try:
        check_image(args.image)
    except Exception:
        raise SystemExit('Runtime distribution layer check failed') from None
    print('Runtime layers contain no owner distribution bundle or builder inputs')


if __name__ == '__main__':
    main()
