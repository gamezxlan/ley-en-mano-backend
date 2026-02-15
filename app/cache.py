import os
from google import genai
from google.genai import types

MODEL_NAME = "gemini-2.5-flash"

client = genai.Client()

cache = None


def load_files():
    context_path = os.environ["CONTEXT_PATH"]
    instruction_path = os.environ["INSTRUCTION_PATH"]

    with open(context_path, "r", encoding="utf-8") as f:
        leyes = f.read()

    with open(instruction_path, "r", encoding="utf-8") as f:
        instruction = f.read()

    return leyes, instruction


def create_cache():
    global cache

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
            system_instruction=[types.Part(text=instruction)],
            ttl="900s",
        ),
    )

    print("========================================")
    print("¡CACHE LEGAL CARGADO!")
    print("CACHE ID:", cache.name)
    print("========================================")

    return cache


def get_cache():
    return cache