from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from google import genai
from .cache import get_cache
from .cache import MODEL_NAME
import os

router = APIRouter()

client = genai.Client(
    api_key=os.environ["GOOGLE_API_KEY"]
)


class Consulta(BaseModel):
    pregunta: str


@router.post("/consultar")
def consultar(data: Consulta):
    cache = get_cache()

    if not cache:
        raise HTTPException(
            status_code=503,
            detail="Sistema legal no inicializado aún"
        )

    response = client.models.generate_content(
        model=MODEL_NAME,
        cached_content=cache.name,  # ✅ AQUÍ VA EL CACHÉ
        contents=[
            {
                "role": "user",
                "parts": [{"text": data.pregunta}]
            }
        ]
    )

    return {
        "respuesta": response.text
    }