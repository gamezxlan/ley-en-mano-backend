from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from google import genai
from .cache import get_cache
from .gemini import MODEL_NAME

router = APIRouter()
client = genai.Client()


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

    model = client.models.get(
        model=MODEL_NAME,
        cached_content=cache.name
    )

    response = model.generate_content(data.pregunta)

    return response.text