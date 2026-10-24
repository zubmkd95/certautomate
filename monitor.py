"""Expiry checks: local files and live TLS endpoints."""
import ssl
from datetime import datetime, timezone

from .ca import cert_not_after, pem_not_after


def days_left(dt: datetime) -> int:
    return (dt - datetime.now(timezone.utc)).days


def live_not_after(host: str, port: int = 443, timeout: int = 8):
    try:
        pem = ssl.get_server_certificate((host, port), timeout=timeout)
        return pem_not_after(pem)
    except Exception:
        return None


def local_not_after(ca, name: str):
    p = ca.issued_dir / name / "cert.pem"
    return cert_not_after(p) if p.exists() else None
