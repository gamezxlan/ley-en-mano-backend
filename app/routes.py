from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from google import genai
from google.genai import types
from .cache import get_cache, MODEL_NAME
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

    return {
        "respuesta": response.text
    }