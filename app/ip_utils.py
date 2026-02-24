# app/ip_utils.py
import os, hashlib
from fastapi import Request

IP_PEPPER = os.getenv("IP_PEPPER", "")  # setear en prod

def get_client_ip(request: Request) -> str:
    """
    Obtiene IP real detrás de proxy (Railway / Nginx / LB).
    Prioridad: X-Forwarded-For (primer IP) > X-Real-IP > request.client.host
    """
    xff = request.headers.get("x-forwarded-for")
    if xff:
        # Puede venir: "IPcliente, IPproxy1, IPproxy2"
        ip = xff.split(",")[0].strip()
        if ip:
            return ip

    xri = request.headers.get("x-real-ip")
    if xri:
        return xri.strip()

    # fallback (proxy)
    return request.client.host if request.client else "unknown"

def hash_ip(ip: str) -> str:
    base = f"{IP_PEPPER}:{ip}" if IP_PEPPER else ip
    return hashlib.sha256(base.encode("utf-8")).hexdigest()