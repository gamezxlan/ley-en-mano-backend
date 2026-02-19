# app/cache.py
import os
import time
from google import genai
from google.genai import types
from .cache_global import LEGAL_CACHE_FLASH, LEGAL_CACHE_LITE

MODEL_FLASH = "models/gemini-2.5-flash"
MODEL_LITE = "models/gemini-2.5-flash-lite"

client = genai.Client(api_key=os.environ["GOOGLE_API_KEY"])


def load_files():
    context_path = os.environ["CONTEXT_PATH"]
    instruction_path = os.environ["INSTRUCTION_PATH"]

    with open(context_path, "r", encoding="utf-8") as f:
        leyes = f.read()

    with open(instruction_path, "r", encoding="utf-8") as f:
        instruction = f.read()

    return leyes, instruction


def _create_cache_for(model_name: str, cache_ref: dict, display_name: str):
    leyes, instruction = load_files()

    cache = client.caches.create(
        model=model_name,
        config=types.CreateCachedContentConfig(
            display_name=display_name,
            contents=[
                types.Content(
                    role="user",
                    parts=[types.Part(text=leyes)]
                )
            ],
            system_instruction=[
                types.Part(text=instruction)
            ],
            ttl=f"{cache_ref['ttl']}s",
        ),
    )

    cache_ref["cache"] = cache
    cache_ref["created_at"] = time.time()

    print("========================================")
    print("¡CACHE LEGAL CARGADO!")
    print("MODEL:", model_name)
    print("CACHE ID:", cache.name)
    print("TTL:", cache_ref["ttl"], "segundos")
    print("========================================")

    return cache


def create_caches():
    # Crea ambos caches al arranque
    _create_cache_for(MODEL_LITE, LEGAL_CACHE_LITE, "ley_en_mano_lite_v1")
    _create_cache_for(MODEL_FLASH, LEGAL_CACHE_FLASH, "ley_en_mano_flash_v1")


def get_cache(kind: str):
    """
    kind: 'lite' | 'flash'
    """
    now = time.time()
    cache_ref = LEGAL_CACHE_LITE if kind == "lite" else LEGAL_CACHE_FLASH
    model_name = MODEL_LITE if kind == "lite" else MODEL_FLASH
    display = "ley_en_mano_lite_v1" if kind == "lite" else "ley_en_mano_flash_v1"

    if cache_ref["cache"] is None:
        print("⚠️ Cache inexistente, creando...")
        return _create_cache_for(model_name, cache_ref, display)

    if now - cache_ref["created_at"] > cache_ref["ttl"]:
        print("⚠️ Cache expirado, recreando...")
        return _create_cache_for(model_name, cache_ref, display)

    return cache_ref["cache"]