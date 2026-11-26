"""File discovery, encoding detection, fail-safe quarantine."""
import hashlib, os

TEXT_EXT = {".txt", ".md", ".note"}
CSV_EXT = {".csv", ".tsv"}
JSON_EXT = {".json"}
KNOWN = TEXT_EXT | CSV_EXT | JSON_EXT

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def walk(root: str):
    for dp, dns, fns in os.walk(root):
        dns.sort()
        for fn in sorted(fns):
            p = os.path.join(dp, fn)
            yield p, os.path.relpath(p, root)

def decode_bytes(raw: bytes) -> str:
    """BOMs, then utf-8, then legacy encodings. Raises ValueError if nothing sane."""
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8")
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    for enc in ("utf-8", "cp1252", "latin-1"):
        try:
            txt = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        if "\x00" not in txt:
            return txt
    raise ValueError("undecodable")
