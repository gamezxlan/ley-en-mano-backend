import os
from fastapi import Header, HTTPException, status, Request

API_KEY = os.environ.get("API_KEY_LEY_EN_MANO")


def verify_api_key(
    request: Request,
    x_api_key: str = Header(None)
):
    if not API_KEY or x_api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key inválida o faltante",
        )

    # 🔐 Guardamos la API Key validada para uso interno
    request.state.api_key = x_api_key