import time

# IP → { count, blocked_until }
BLOCKS = {}

# Configuración
MAX_REQUESTS = 5          # intentos antes de castigo
WINDOW_SECONDS = 60       # ventana de conteo
BLOCK_TIME = 300          # 5 minutos


def check_ip(ip: str):
    now = time.time()

    record = BLOCKS.get(ip)

    # IP ya bloqueada
    if record and record.get("blocked_until", 0) > now:
        return False, int(record["blocked_until"] - now)

    # Inicializar
    if not record or now - record["start"] > WINDOW_SECONDS:
        BLOCKS[ip] = {
            "count": 1,
            "start": now
        }
        return True, 0

    # Incrementar
    record["count"] += 1

    if record["count"] > MAX_REQUESTS:
        record["blocked_until"] = now + BLOCK_TIME
        return False, BLOCK_TIME

    return True, 0