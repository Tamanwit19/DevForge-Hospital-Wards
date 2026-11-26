"""Keyed pseudonyms and per-patient date shifts. Secret comes only from env."""
import hmac, hashlib, os, sys

_B32 = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

def _secret() -> bytes:
    s = os.environ.get("RAKSHA_SECRET")
    if not s:
        sys.exit("RAKSHA_SECRET not set")
    return s.encode()

def _mac(domain: str, msg: str) -> bytes:
    return hmac.new(_secret(), f"{domain}|{msg}".encode(), hashlib.sha256).digest()

def pseudonym(cluster_key: str) -> str:
    """Stable, non-reversible ID. cluster_key = canonical identity of the cluster."""
    n = int.from_bytes(_mac("psn", cluster_key)[:8], "big")
    out = []
    for _ in range(8):
        out.append(_B32[n % len(_B32)]); n //= len(_B32)
    return "PSN-" + "".join(out)

def date_shift_days(patient_id: str, span: int = 180) -> int:
    """Same patient -> same shift everywhere, so intervals/stay length are preserved."""
    return int.from_bytes(_mac("shift", patient_id)[:4], "big") % (2 * span + 1) - span

def token(kind: str, value: str, n: int = 8) -> str:
    """Deterministic placeholder for non-patient entities (e.g. relatives)."""
    return f"[{kind}-{_mac('tok:'+kind, value).hex()[:n].upper()}]"


def resource_uuid(original: str) -> str:
    """Release-keyed UUID, with stable variant/version bits."""
    import uuid
    return str(uuid.UUID(bytes=_mac("fhir-resource", original)[:16], version=4))
