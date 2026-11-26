"""Offline encryption of an already reviewed sanitized release.
This is not called by the challenge CLI. Does not encrypt or modify raw input.
"""
import argparse,base64,io,os,secrets,zipfile
from pathlib import Path
MAGIC=b'RAKSHA-ENC1'
MAX_BYTES=100*1024*1024

def key_from_env():
    raw=os.environ.get('RAKSHA_ARCHIVE_KEY','')
    try: key=base64.b64decode(raw,altchars=b'-_',validate=True)
    except ValueError: raise ValueError('Invalid archive key encoding') from None
    if len(key)!=32: raise ValueError('Archive key must be 32 random bytes, base64 encoded')
    return key

def encrypt_release(root,destination,key):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    root=Path(root).resolve(); destination=Path(destination).resolve()
    if not (root/'sanitized').is_dir() or not (root/'report.json').is_file() or not (root/'records.jsonl').is_file():
        raise ValueError('Expected a sanitized release directory')
    if root==destination or root in destination.parents: raise ValueError('Archive must be outside release directory')
    files=[root/'report.json',root/'records.jsonl']+sorted(p for p in (root/'sanitized').rglob('*') if p.is_file())
    if any(p.is_symlink() or root not in p.resolve().parents for p in files): raise ValueError('Unsafe release path')
    size=sum(p.stat().st_size for p in files)
    if size>MAX_BYTES: raise ValueError('Release archive exceeds in-memory limit')
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w',compression=zipfile.ZIP_DEFLATED) as archive:
        for p in files: archive.writestr(p.relative_to(root).as_posix(),p.read_bytes())
    nonce=secrets.token_bytes(12)
    encrypted=MAGIC+nonce+AESGCM(key).encrypt(nonce,buf.getvalue(),MAGIC)
    with destination.open('xb') as f: f.write(encrypted)

def decrypt_bytes(blob,key):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if not blob.startswith(MAGIC) or len(blob)<len(MAGIC)+28: raise ValueError('Invalid encrypted archive')
    start=len(MAGIC)
    return AESGCM(key).decrypt(blob[start:start+12],blob[start+12:],MAGIC)

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--release',required=True);p.add_argument('--output',required=True)
    a=p.parse_args()
    try: encrypt_release(a.release,a.output,key_from_env())
    except (ValueError,OSError,ImportError): p.exit(1,'Archive creation refused; check paths, key and dependency.\n')
    print('Encrypted archive created.')
