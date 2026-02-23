# app/auth_repo.py
from __future__ import annotations
from uuid import uuid4
from datetime import datetime, timedelta, timezone
import hashlib
import os
from .db import pool

SESSION_PEPPER = os.getenv("SESSION_PEPPER", "")

def _hash_session(session_id: str) -> str:
    base = f"{SESSION_PEPPER}:{session_id}" if SESSION_PEPPER else session_id
    return hashlib.sha256(base.encode("utf-8")).hexdigest()

def upsert_user_by_email(email: str) -> str:
    email = email.strip().lower()
    user_id = str(uuid4())

    with pool.connection() as conn:
        with conn.cursor() as cur:
            # si ya existe email, regresa user_id existente
            cur.execute("SELECT user_id FROM users WHERE email = %s", (email,))
            row = cur.fetchone()
            if row:
                return str(row[0])

            cur.execute(
                "INSERT INTO users(user_id, email, created_at) VALUES (%s, %s, NOW())",
                (user_id, email),
            )
        conn.commit()

    return user_id

def create_session(user_id: str, days: int = 14, ip: str | None = None, user_agent: str | None = None) -> str:
    session_id = str(uuid4())
    session_hash = _hash_session(session_id)
    expires_at = datetime.now(timezone.utc) + timedelta(days=days)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO sessions(
                  session_id_hash, user_id,
                  created_at, last_seen_at,
                  expires_at, ip, user_agent,
                  revoked_at
                )
                VALUES (%s, %s, NOW(), NOW(), %s, %s, %s, NULL)
                """,
                (session_hash, user_id, expires_at, ip, user_agent),
            )
        conn.commit()

    return session_id