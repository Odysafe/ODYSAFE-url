#!/usr/bin/env python3
"""Maintainer-only offline packager. Exports images, never containers or volumes."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import signal
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent.parent
BLOCKED = {'.git', '.codex', '.agents', '.aws', '.ssh', '.history', '.cache',
           '__pycache__', '.pytest_cache', '.venv', 'dist', 'backups', 'data', 'logs'}
PRIVATE = re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|'
                     rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|'
                     rb'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b|'
                     rb'/(?:home/(?!odysafe(?:/|\b))|Users/)[A-Za-z0-9_.-]+/')
ALLOWED_ROOT = {'README.md', 'start.dh', 'stop', '.gitignore'}
ALLOWED_DIRS = {'application', 'tools', 'LICENCES'}


def run(*args):
    return subprocess.check_output(args)


def image_references():
    references = []
    for line in (ROOT/'application/release-images.env').read_text().splitlines():
        if not line or line.startswith('#'): continue
        key, value = line.split('=', 1)
        if not re.fullmatch(r'ODYSAFE_IMAGE_(APP|INTERACTIVE|GATEWAY|FIXTURE|PROXY)', key):
            raise ValueError('Unexpected release image variable')
        if not re.fullmatch(r'odysafe-source-(app|interactive|gateway|fixture|proxy):[0-9]+\.[0-9]+\.[0-9]+', value):
            raise ValueError('Expected a versioned local release image, without credentials')
        references.append(value)
    if len(set(references)) != 5: raise ValueError('Expected exactly five release images')
    return sorted(references)


def source_files():
    result = []
    for path in sorted(ROOT.rglob('*')):
        relative = path.relative_to(ROOT)
        if relative.parts[0] not in ALLOWED_DIRS and relative.as_posix() not in ALLOWED_ROOT: continue
        if any(part in BLOCKED or part.endswith('.egg-info') for part in relative.parts): continue
        if path.is_symlink(): raise ValueError(f'Symbolic link refused: {relative}')
        if not path.is_file(): continue
        if path.name.startswith('.env') or (path.suffix == '.env' and path.name != 'release-images.env') or path.name == 'installation.env' or path.suffix in {'.db','.sqlite','.sqlite3','.har','.key','.pem','.pyc','.pyo','.tmp','.partial','.tar','.gz','.log','.bak','.xlsx','.zip'}:
            raise ValueError(f'Local data or build residue refused: {relative}')
        raw = path.read_bytes()
        if b'\0' not in raw and PRIVATE.search(raw):
            raise ValueError(f'Potential private content in {relative}; inspect before packaging')
        result.append(path)
    return result


def audit_image(reference):
    metadata = json.loads(run('docker', 'image', 'inspect', reference))[0]
    if metadata['Os'] != 'linux' or metadata['Architecture'] != 'amd64':
        raise ValueError(f'Unsupported image architecture: {reference}')
    if PRIVATE.search(json.dumps(metadata['Config']).encode()):
        raise ValueError(f'Potential private image configuration: {reference}')
    config = metadata['Config']
    if config.get('Volumes'): raise ValueError('Release image must not declare embedded runtime volumes')
    for entry in config.get('Env', []):
        name = entry.split('=', 1)[0]
        if re.search(r'TOKEN|SECRET|PASSWORD|CREDENTIAL|ACCESS_KEY', name, re.I):
            raise ValueError(f'Credential environment variable embedded in {reference}: {name}')
    container = run('docker','create','--network','none','--read-only','--entrypoint','/bin/true',reference).decode().strip()
    process = None
    try:
        process = subprocess.Popen(['docker','container','export',container], stdout=subprocess.PIPE)
        assert process.stdout is not None
        files = 0
        application_files = set()
        with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
            for member in archive:
                path = PurePosixPath(member.name)
                if member.isfile():
                    files += 1
                    parts = path.parts
                    if any(part in {'.codex','.agents','.aws','.ssh','.history','.pytest_cache'} for part in parts):
                        raise ValueError(f'Private development files embedded in {reference}: {path}')
                    if parts and parts[0] in {'data','database','backups','certificates'}:
                        raise ValueError(f'Runtime data embedded in {reference}: {path}')
                    if path.name == 'installation.env' or ('.cache' in parts and parts[0] in {'root','home'}):
                        raise ValueError(f'Local configuration or download cache in {reference}: {path}')
                    if parts and parts[0] in {'tmp','run'} and path.name != '.wh..wh..opq':
                        raise ValueError(f'Temporary build files embedded in {reference}: {path}')
                    if reference.startswith('odysafe-source-interactive:') and any(part.startswith('chromium_headless_shell-') for part in parts):
                        raise ValueError('Rebuild the compact image: an unused Chromium headless shell is still present')
                    # Compare the shipped application with this source checkout.
                    if path.as_posix().startswith('opt/odysafe/app/'):
                        relative = path.relative_to('opt/odysafe')
                        application_files.add(relative.as_posix())
                        local = ROOT/'application'/relative
                        if not local.is_file(): raise ValueError(f'Unexpected application file: {path}')
                        content = archive.extractfile(member)
                        if content is None or hashlib.sha256(content.read()).digest() != hashlib.sha256(local.read_bytes()).digest():
                            raise ValueError(f'Image is stale; rebuild before packaging: {path}')
        if reference.startswith(('odysafe-source-app:', 'odysafe-source-interactive:')):
            expected = {p.relative_to(ROOT/'application').as_posix() for p in (ROOT/'application/app').rglob('*') if p.is_file()}
            if application_files != expected: raise ValueError('Image application files differ from the current source checkout')
        process.stdout.close()
        if process.wait() != 0: raise RuntimeError('Docker image audit export failed')
        return {'reference': reference, 'id':metadata['Id'], 'platform':'linux/amd64', 'files_checked':files}
    finally:
        if process is not None and process.poll() is None:
            process.kill(); process.wait(timeout=10)
        subprocess.run(['docker','rm','-f',container],check=True,stdout=subprocess.DEVNULL)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path, nargs='?', help='Output .tar.gz file; --audit-only needs no output')
    parser.add_argument('--audit-only', action='store_true')
    args = parser.parse_args()
    if not args.audit_only and (args.output is None or not str(args.output).endswith('.tar.gz')):
        parser.error('Supply an output .tar.gz file or --audit-only')
    if args.output is not None and args.output.exists(): parser.error('Output already exists; refusing to overwrite it')
    files = source_files()
    reports = []
    for reference in image_references():
        report = audit_image(reference)
        reports.append(report)
        print(f'Audited {reference}: {report["files_checked"]} files; no runtime data or local secrets found', flush=True)
    if args.audit_only: return
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    partial = output.with_name(output.name+'.partial')
    if partial.exists(): raise ValueError('A partial output already exists; inspect it first')
    prefix = 'odysafe-url'
    try:
        with tempfile.TemporaryDirectory(prefix='odysafe-offline-') as temporary:
            staging = Path(temporary)
            image_tar = staging/'images.tar'
            subprocess.run(['docker','image','save','--output',str(image_tar),*[r['reference'] for r in reports]],check=True)
            image_sha = staging/'images.tar.sha256'
            image_sha.write_text(digest(image_tar)+'  images.tar\n')
            image_ids = staging/'images.ids'
            image_ids.write_text(''.join(r['id']+'  '+r['reference']+'\n' for r in reports))
            manifest = staging/'distribution.json'
            manifest.write_text(json.dumps({'format':1,'platform':'linux/amd64','images':reports,
                                            'contents':'Public source and pristine images only; no containers, volumes, Git history or installation configuration'},indent=2)+'\n')
            with tarfile.open(partial,'w:gz',compresslevel=9) as archive:
                def normalize(info):
                    info.uid=info.gid=0; info.uname=info.gname=''; info.mtime=0
                    info.pax_headers={}
                    return info
                for path in files:
                    archive.add(path, arcname=f'{prefix}/{path.relative_to(ROOT).as_posix()}', recursive=False, filter=normalize)
                for path in (image_tar,image_sha,image_ids,manifest):
                    archive.add(path,arcname=f'{prefix}/{path.name}',recursive=False,filter=normalize)
            partial.replace(output)
            output.with_name(output.name+'.sha256').write_text(digest(output)+'  '+output.name+'\n')
            print(f'Offline bundle: {output.name} ({output.stat().st_size:,} bytes)',flush=True)
    finally:
        partial.unlink(missing_ok=True)


if __name__ == '__main__':
    def terminate(*_):
        raise SystemExit(143)
    signal.signal(signal.SIGTERM, terminate)
    main()
