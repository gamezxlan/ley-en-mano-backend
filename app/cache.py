import os
import time
from google import genai
from google.genai import types
from .cache_global import LEGAL_CACHE

MODEL_NAME = "models/gemini-2.5-flash"

client = genai.Client(
    api_key=os.environ["GOOGLE_API_KEY"]
)


def load_files():
    context_path = os.environ["CONTEXT_PATH"]
    instruction_path = os.environ["INSTRUCTION_PATH"]

    with open(context_path, "r", encoding="utf-8") as f:
        leyes = f.read()

    with open(instruction_path, "r", encoding="utf-8") as f:
        instruction = f.read()

    return leyes, instruction


def create_cache():
    leyes, instruction = load_files()

    cache = client.caches.create(
        model=MODEL_NAME,
        config=types.CreateCachedContentConfig(
            display_name="ley_en_mano_v1",
            contents=[
                types.Content(
                    role="user",
                    parts=[types.Part(text=leyes)]
                )
            ],
            system_instruction=[
                types.Part(text=instruction)
            ],
            ttl=f"{LEGAL_CACHE['ttl']}s",
        ),
    )

    LEGAL_CACHE["cache"] = cache
    LEGAL_CACHE["created_at"] = time.time()

    print("========================================")
    print("¡CACHE LEGAL CARGADO!")
    print("CACHE ID:", cache.name)
    print("TTL:", LEGAL_CACHE["ttl"], "segundos")
    print("========================================")

    return cache


def get_cache():
    now = time.time()

    if LEGAL_CACHE["cache"] is None:
        print("⚠️ Cache inexistente, creando...")
        return create_cache()

    if now - LEGAL_CACHE["created_at"] > LEGAL_CACHE["ttl"]:
        print("⚠️ Cache expirado, recreando...")
        return create_cache()

    return LEGAL_CACHE["cache"]