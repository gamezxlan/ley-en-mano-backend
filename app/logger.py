import os
from datetime import datetime

LOG_PATH = os.environ.get("LOG_PATH", "/app/context/logs/consultas.log")

def log_consulta(ip: str, pregunta: str):
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(
            f"[{datetime.utcnow().isoformat()}] IP={ip} | {pregunta}\n"
        )