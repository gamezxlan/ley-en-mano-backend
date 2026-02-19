# app/cache_global.py

DEFAULT_TTL = 3600  # 1 hora

LEGAL_CACHE_FLASH = {
    "cache": None,
    "created_at": 0,
    "ttl": DEFAULT_TTL
}

LEGAL_CACHE_LITE = {
    "cache": None,
    "created_at": 0,
    "ttl": DEFAULT_TTL
}