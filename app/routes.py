from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from google import genai
from google.genai import types
from .cache import get_cache, MODEL_NAME
from .security import verify_api_key
from .ratelimit import limiter
from .logger import log_consulta
from .blocklist import check_ip_key
import os

router = APIRouter()

client = genai.Client(
    api_key=os.environ["GOOGLE_API_KEY"]
)

class Consulta(BaseModel):
    pregunta: str


@router.post("/consultar", dependencies=[Depends(verify_api_key)])
@limiter.limit("5/minute")
def consultar(request: Request, data: Consulta):
    ip = request.client.host
    api_key = request.state.api_key

    allowed, wait = check_ip_key(ip, api_key)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"IP bloqueada temporalmente. Intenta de nuevo en {wait} segundos."
        )

    cache = get_cache()
    if not cache:
        raise HTTPException(
            status_code=503,
            detail="Sistema legal no disponible. Intenta nuevamente en unos minutos."
        )

    log_consulta(ip, data.pregunta)

    response = client.models.generate_content(
        model=MODEL_NAME,
        contents=[
            types.Content(
                role="user",
                parts=[types.Part(text=data.pregunta)]
            )
        ],
        config=types.GenerateContentConfig(
            cached_content=cache.name
        )
    )

    # 🔒 GUARDRAIL JSON ESTRICTO (ANTI-DERIVA)
    text = response.text.strip()
    print(text)
    print("-----------------")
    print(response.text.strip())
    if not text.startswith("{") or not text.endswith("}"):
        raise HTTPException(
            status_code=502,
            detail="Respuesta legal inválida. Reintenta."
        )

    return {
        "respuesta": text
    }