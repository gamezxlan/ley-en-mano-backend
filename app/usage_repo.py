# app/usage_repo.py
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from uuid import uuid4
from .db import pool

MX_TZ = ZoneInfo("America/Mexico_City")
UTC = ZoneInfo("UTC")


@dataclass
class UsageCounts:
    day_used: int
    month_used: int


def upsert_visitor(visitor_id: str, user_id: str | None):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO visitors(visitor_id, user_id, created_at, last_seen_at)
                VALUES (%s, %s, NOW(), NOW())
                ON CONFLICT (visitor_id)
                DO UPDATE SET
                  user_id = COALESCE(EXCLUDED.user_id, visitors.user_id),
                  last_seen_at = NOW()
                """,
                (visitor_id, user_id),
            )
        conn.commit()


def ensure_user(user_id: str):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users(user_id, email, created_at)
                VALUES (%s, NULL, NOW())
                ON CONFLICT (user_id) DO NOTHING
                """,
                (user_id,),
            )
        conn.commit()


# ======================================================
# ENTITLEMENTS (NUEVO CORE)
# ======================================================

def _expire_entitlements(user_id: str):
    """
    1) Marca como expired si valid_until ya pasó
    2) Marca como quota_exhausted si remaining <= 0
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE entitlements
                SET status = 'expired'
                WHERE user_id = %s
                  AND status = 'active'
                  AND valid_until <= NOW()
                """,
                (user_id,),
            )
            cur.execute(
                """
                UPDATE entitlements
                SET status = 'quota_exhausted'
                WHERE user_id = %s
                  AND status = 'active'
                  AND remaining <= 0
                  AND valid_until > NOW()
                """,
                (user_id,),
            )
        conn.commit()


def get_active_entitlement(user_id: str):
    """
    Devuelve el entitlement USABLE del usuario (premium real).

    Regla:
    - Expira por tiempo y marca quota_exhausted si remaining <= 0
    - Devuelve SOLO:
      status='active', valid_until > NOW(), remaining > 0
    - Si no hay uno usable -> None
    """
    _expire_entitlements(user_id)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT entitlement_id, plan_code, quota_total, remaining, valid_until, status, created_at
                FROM entitlements
                WHERE user_id = %s
                  AND status = 'active'
                  AND valid_until > NOW()
                  AND remaining > 0
                ORDER BY valid_until DESC, created_at DESC
                LIMIT 1
                """,
                (user_id,),
            )
            row = cur.fetchone()

    if not row:
        return None

    return {
        "entitlement_id": row[0],
        "plan_code": row[1],
        "quota_total": int(row[2]),
        "remaining": int(row[3]),
        "valid_until": row[4],
        "status": row[5],
        "created_at": row[6],
    }

def get_latest_entitlement_any_status(user_id: str):
    """
    Devuelve el entitlement más reciente del usuario aunque esté quota_exhausted o expired.
    Útil para UI (mostrar 'agotado' / 'vencido').
    """
    _expire_entitlements(user_id)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT entitlement_id, plan_code, quota_total, remaining, valid_until, status, created_at
                FROM entitlements
                WHERE user_id = %s
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (user_id,),
            )
            row = cur.fetchone()

    if not row:
        return None

    return {
        "entitlement_id": row[0],
        "plan_code": row[1],
        "quota_total": int(row[2]),
        "remaining": int(row[3]),
        "valid_until": row[4],
        "status": row[5],
        "created_at": row[6],
    }

# ======================================================
# UPGRADE HELPERS
# ======================================================

def expire_entitlement(entitlement_id: str, *, note: str | None = None):
    """
    Marca un entitlement como expired (por upgrade u otra razón).
    """
    if not entitlement_id:
        return
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE entitlements
                SET status = 'expired'
                WHERE entitlement_id = %s
                """,
                (entitlement_id,),
            )
        conn.commit()


def get_entitlement_by_id(entitlement_id: str):
    if not entitlement_id:
        return None
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT entitlement_id, user_id, plan_code, quota_total, remaining, valid_until, status, created_at
                FROM entitlements
                WHERE entitlement_id = %s
                """,
                (entitlement_id,),
            )
            row = cur.fetchone()

    if not row:
        return None

    return {
        "entitlement_id": row[0],
        "user_id": row[1],
        "plan_code": row[2],
        "quota_total": int(row[3]),
        "remaining": int(row[4]),
        "valid_until": row[5],
        "status": row[6],
        "created_at": row[7],
    }


def consume_entitlement(user_id: str):
    """
    Descuenta 1 consulta de forma ATÓMICA.

    - Selecciona un entitlement activo, vigente, remaining > 0
    - Lo bloquea FOR UPDATE
    - Decrementa remaining
    - Si queda en 0, lo marca quota_exhausted

    Devuelve dict con entitlement_id, plan_code, remaining_after, valid_until, status
    o None si no hay cupo.
    """
    _expire_entitlements(user_id)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            # Elegimos el "mejor" paquete activo que aún tenga saldo.
            cur.execute(
                """
                SELECT entitlement_id, plan_code, remaining, valid_until
                FROM entitlements
                WHERE user_id = %s
                  AND status = 'active'
                  AND valid_until > NOW()
                  AND remaining > 0
                ORDER BY valid_until DESC, created_at DESC
                FOR UPDATE
                LIMIT 1
                """,
                (user_id,),
            )
            row = cur.fetchone()

            if not row:
                conn.commit()
                return None

            entitlement_id, plan_code, remaining, valid_until = row
            remaining_after = int(remaining) - 1

            new_status = "quota_exhausted" if remaining_after <= 0 else "active"

            cur.execute(
                """
                UPDATE entitlements
                SET remaining = %s,
                    status = %s
                WHERE entitlement_id = %s
                """,
                (max(0, remaining_after), new_status, entitlement_id),
            )
        conn.commit()

    return {
        "entitlement_id": entitlement_id,
        "plan_code": plan_code,
        "remaining_after": max(0, remaining_after),
        "valid_until": valid_until,
        "status": new_status,
    }


def refund_entitlement(entitlement_id):
    """
    Devuelve 1 consulta al entitlement.
    Úsalo si decidimos 'consumir antes' y luego falla Gemini/JSON.
    """
    if not entitlement_id:
        return

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE entitlements
                SET remaining = remaining + 1,
                    status = 'active'
                WHERE entitlement_id = %s
                  AND valid_until > NOW()
                """,
                (entitlement_id,),
            )
        conn.commit()


# ======================================================
# FREE/GUEST LIMITS (IGUAL QUE ANTES)
# ======================================================

def _day_window_mx(now: datetime):
    local = now.astimezone(MX_TZ)
    start = local.replace(hour=0, minute=0, second=0, microsecond=0)
    end = start + timedelta(days=1)
    return start.astimezone(UTC), end.astimezone(UTC)


def count_day_usage(visitor_id: str, user_id: str | None) -> int:
    now = datetime.now(tz=UTC)
    start_utc, end_utc = _day_window_mx(now)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            if user_id:
                cur.execute(
                    """
                    SELECT COUNT(*)
                    FROM usage_events
                    WHERE user_id = %s
                      AND allowed = TRUE
                      AND created_at >= %s AND created_at < %s
                    """,
                    (user_id, start_utc, end_utc),
                )
            else:
                cur.execute(
                    """
                    SELECT COUNT(*)
                    FROM usage_events
                    WHERE visitor_id = %s
                      AND allowed = TRUE
                      AND created_at >= %s AND created_at < %s
                    """,
                    (visitor_id, start_utc, end_utc),
                )
            row = cur.fetchone()
    return int(row[0]) if row else 0


def count_day_usage_by_ip(ip_hash: str) -> int:
    now = datetime.now(tz=UTC)
    start_utc, end_utc = _day_window_mx(now)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM usage_events
                WHERE ip_hash = %s
                  AND allowed = TRUE
                  AND endpoint = '/consultar'
                  AND created_at >= %s AND created_at < %s
                """,
                (ip_hash, start_utc, end_utc),
            )
            row = cur.fetchone()
    return int(row[0]) if row else 0


def insert_usage_event(
    visitor_id: str,
    user_id: str | None,
    profile: str,
    plan_code: str | None,
    model_used: str,
    endpoint: str,
    allowed: bool,
    reason: str | None,
    ip_hash: str | None,
    entitlement_id=None,  # <-- NUEVO
):
    event_id = str(uuid4())
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO usage_events(
                  event_id, visitor_id, user_id, profile, plan_code, model_used,
                  endpoint, allowed, reason, ip_hash, entitlement_id, created_at
                )
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())
                """,
                (
                    event_id,
                    visitor_id,
                    user_id,
                    profile,
                    plan_code,
                    model_used,
                    endpoint,
                    allowed,
                    reason,
                    ip_hash,
                    entitlement_id,
                ),
            )
        conn.commit()