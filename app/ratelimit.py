# app/ratelimit.py
from slowapi import Limiter
from fastapi import Request

def get_real_ip(request: Request) -> str:
    """
    Railway/Proxy-friendly:
    - Usa X-Forwarded-For si existe (primer IP)
    - Si no, request.client.host
    """
    xff = request.headers.get("x-forwarded-for")
    if xff:
        # Puede venir: "ip1, ip2, ip3"
        return xff.split(",")[0].strip()

    if request.client and request.client.host:
        return request.client.host

    return "unknown"

limiter = Limiter(key_func=get_real_ip)