# app/ip_utils.py
from fastapi import Request

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