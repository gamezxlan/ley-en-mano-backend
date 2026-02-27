import os
import json
import time
import hashlib
from threading import Lock
from dataclasses import dataclass

BLOCK_FILE = os.environ.get("BLOCK_FILE", "/app/context/logs/blocks.json")
LOCK = Lock()


@dataclass
class Limits:
    max_requests: int
    window_seconds: int
    block_time: int


# 👇 Ajusta aquí tus políticas por endpoint (recomendación inicial)
ENDPOINT_LIMITS = {
    "/consultar": Limits(max_requests=15, window_seconds=300, block_time=1800),  # 15 en 5 min, bloquea 30 min
    "/policy":    Limits(max_requests=120, window_seconds=300, block_time=600),  # 120 en 5 min, bloquea 10 min
}


def _hash_key(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def _load_blocks():
    if not os.path.exists(BLOCK_FILE):
        return {}
    try:
        with open(BLOCK_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_blocks(data):
    os.makedirs(os.path.dirname(BLOCK_FILE), exist_ok=True)
    with open(BLOCK_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)


def _check_and_bump(blocks: dict, key: str, now: float, lim: Limits):
    rec = blocks.get(key)

    # bloqueado
    if rec and rec.get("blocked_until", 0) > now:
        return False, int(rec["blocked_until"] - now)

    # nueva ventana
    if (not rec) or (now - rec.get("start", now) > lim.window_seconds):
        blocks[key] = {"count": 1, "start": now}
        return True, 0

    # incremento
    rec["count"] = int(rec.get("count", 0)) + 1

    if rec["count"] > lim.max_requests:
        rec["blocked_until"] = now + lim.block_time
        return False, lim.block_time

    return True, 0


def check_identity(*, ip: str, visitor_id: str, endpoint: str):
    """
    Rate limit por:
      - IP (ip::<endpoint>::<ip>)
      - Visitor (v::<endpoint>::<visitor_hash>)
      - Pair (pair::<endpoint>::<ip>::<visitor_hash>)  [extra]
    Bloquea si CUALQUIERA excede.

    Devuelve: (allowed: bool, wait_seconds: int, reason: str|None)
    """
    now = time.time()
    lim = ENDPOINT_LIMITS.get(endpoint) or ENDPOINT_LIMITS["/consultar"]

    vhash = _hash_key(visitor_id or "none")
    ip_key = f"ip::{endpoint}::{ip}"
    v_key = f"v::{endpoint}::{vhash}"
    pair_key = f"pair::{endpoint}::{ip}::{vhash}"

    with LOCK:
        blocks = _load_blocks()

        # 1) si cualquiera está bloqueado, salimos
        for k, why in [(ip_key, "ip"), (v_key, "visitor"), (pair_key, "pair")]:
            rec = blocks.get(k)
            if rec and rec.get("blocked_until", 0) > now:
                _save_blocks(blocks)
                return False, int(rec["blocked_until"] - now), f"blocked:{why}"

        # 2) bump a los 3; si alguno excede -> bloquear
        ok1, w1 = _check_and_bump(blocks, ip_key, now, lim)
        ok2, w2 = _check_and_bump(blocks, v_key, now, lim)
        ok3, w3 = _check_and_bump(blocks, pair_key, now, lim)

        _save_blocks(blocks)

        if ok1 and ok2 and ok3:
            return True, 0, None

        # wait = máximo de waits
        wait = max(w1, w2, w3)
        reason = "rate_exceeded"
        if not ok1:
            reason = "rate_exceeded:ip"
        elif not ok2:
            reason = "rate_exceeded:visitor"
        else:
            reason = "rate_exceeded:pair"

        return False, int(wait), reason