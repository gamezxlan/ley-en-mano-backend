from fastapi import Request, HTTPException, status
import re

# User-Agents mínimos aceptables (navegadores reales)
UA_PATTERN = re.compile(r"(Mozilla|Chrome|Safari|Firefox|Edge)", re.I)

def verify_antibot(request: Request):
    ua = request.headers.get("user-agent")
    fingerprint = request.headers.get("x-client-fingerprint")

    # ❌ Sin User-Agent
    if not ua or not UA_PATTERN.search(ua):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso denegado (cliente no válido)"
        )

    # ❌ Sin fingerprint (anti-bot)
    if not fingerprint or len(fingerprint) < 16:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso denegado (fingerprint inválido)"
        )