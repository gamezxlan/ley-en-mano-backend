import os
import time
from google import genai
from google.genai import types

MODEL_NAME = "models/gemini-2.5-flash"

client = genai.Client(
    api_key=os.environ["GOOGLE_API_KEY"]
)

cache = None
cache_created_at = 0
CACHE_TTL_SECONDS = 3600  # ⬅️ 1 hora (recomendado)


def load_files():
    context_path = os.environ["CONTEXT_PATH"]
    instruction_path = os.environ["INSTRUCTION_PATH"]

    with open(context_path, "r", encoding="utf-8") as f:
        leyes = f.read()

    with open(instruction_path, "r", encoding="utf-8") as f:
        instruction = f.read()

    return leyes, instruction


def create_cache():
    global cache, cache_created_at

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
            ttl=f"{CACHE_TTL_SECONDS}s",
        ),
    )

    print("========================================")
    print("¡CACHE LEGAL CARGADO!")
    print("CACHE ID:", cache.name)
    print("TTL:", CACHE_TTL_SECONDS, "segundos")
    print("========================================")

    return cache


def get_cache():
    global cache, cache_created_at

    now = time.time()

    # ❌ Cache inexistente
    if cache is None:
        return create_cache()

    # ❌ Cache expirado
    if now - cache_created_at > CACHE_TTL_SECONDS:
        print("⚠️ Cache expirado, recreando...")
        return create_cache()
    return cache