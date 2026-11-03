"""Create and renew the persistent loopback certificate without changing its key."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import time

DIRECTORY=Path(os.environ.get('ODYSAFE_CERT_DIR','/certificates'))
RENEW_BEFORE=60*86400


def maintain_certificate():
    certificate=DIRECTORY/'odysafe.crt';private_key=DIRECTORY/'odysafe.key'
    DIRECTORY.mkdir(parents=True,exist_ok=True)
    for path in (certificate,private_key):
        if path.is_symlink():raise RuntimeError('Certificate paths must not be symbolic links')
    if certificate.is_file() and private_key.is_file():
        check=subprocess.run(['openssl','x509','-checkend',str(RENEW_BEFORE),'-noout','-in',str(certificate)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if check.returncode==0:return False
    temporary_certificate=DIRECTORY/'.odysafe.crt.tmp';temporary_key=DIRECTORY/'.odysafe.key.tmp'
    temporary_certificate.unlink(missing_ok=True);temporary_key.unlink(missing_ok=True)
    uid=int(os.environ.get('ODYSAFE_UID','1000'));gid=int(os.environ.get('ODYSAFE_GID','1000'))
    try:
        command=['openssl','req','-x509','-sha256','-days','730','-subj','/CN=ODYSAFE-URL Local','-addext','subjectAltName=IP:127.0.0.1,DNS:localhost','-out',str(temporary_certificate)]
        # Preserve the private key on renewal; only the certificate changes.
        if private_key.is_file():command+=['-key',str(private_key)]
        else:command+=['-newkey','rsa:3072','-nodes','-keyout',str(temporary_key)]
        subprocess.run(command,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        os.chmod(temporary_certificate,0o644);os.chown(temporary_certificate,uid,gid)
        if temporary_key.exists():
            os.chmod(temporary_key,0o640);os.chown(temporary_key,uid,gid);temporary_key.replace(private_key)
        temporary_certificate.replace(certificate)
        print('Local TLS certificate created or renewed.',flush=True)
        return True
    finally:
        temporary_certificate.unlink(missing_ok=True);temporary_key.unlink(missing_ok=True)


def main():
    if '--watch' not in sys.argv:
        maintain_certificate();return
    while True:
        try:maintain_certificate()
        except Exception as exc:print(f'Certificate renewal failed: {type(exc).__name__}: {exc}',file=sys.stderr,flush=True)
        time.sleep(86400)


if __name__=='__main__':main()
