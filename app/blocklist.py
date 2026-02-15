import os
import json
import time
import hashlib
from threading import Lock

BLOCK_FILE = os.environ.get(
    "BLOCK_FILE",
    "/app/context/logs/blocks.json"
)

LOCK = Lock()

# Configuración
MAX_REQUESTS = 2
WINDOW_SECONDS = 120
BLOCK_TIME = 300  # 5 minutos


def _hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()[:12]


def _load_blocks():
    if not os.path.exists(BLOCK_FILE):
        return {}
    with open(BLOCK_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def _save_blocks(data):
    with open(BLOCK_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)


def check_ip_key(ip: str, api_key: str):
    now = time.time()
    key_hash = _hash_key(api_key)
    identity = f"{ip}::{key_hash}"

    with LOCK:
        blocks = _load_blocks()
        record = blocks.get(identity)

        # 🔒 Bloqueado
        if record and record.get("blocked_until", 0) > now:
            return False, int(record["blocked_until"] - now)

        # 🕒 Nueva ventana
        if not record or now - record["start"] > WINDOW_SECONDS:
            blocks[identity] = {
                "count": 1,
                "start": now
            }
            _save_blocks(blocks)
            return True, 0

        # ➕ Incremento
        record["count"] += 1

        if record["count"] > MAX_REQUESTS:
            record["blocked_until"] = now + BLOCK_TIME
            _save_blocks(blocks)
            return False, BLOCK_TIME

        _save_blocks(blocks)
        return True, 0