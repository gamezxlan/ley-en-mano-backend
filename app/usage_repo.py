# app/usage_repo.py
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from uuid import uuid4
from .db import pool

MX_TZ = ZoneInfo("America/Mexico_City")


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
                (visitor_id, user_id)
            )
        conn.commit()


def get_active_subscription(user_id: str):
    """
    Regresa dict con plan_code, current_period_start, current_period_end si hay subs activa.
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT plan_code, status, current_period_start, current_period_end
                FROM subscriptions
                WHERE user_id = %s
                  AND status = 'active'
                  AND current_period_end > NOW()
                ORDER BY current_period_end DESC
                LIMIT 1
                """,
                (user_id,)
            )
            row = cur.fetchone()
    if not row:
        return None
    return {
        "plan_code": row[0],
        "status": row[1],
        "current_period_start": row[2],
        "current_period_end": row[3],
    }


def get_plan_quota(plan_code: str) -> int:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT monthly_quota FROM plans WHERE plan_code=%s",
                (plan_code,)
            )
            row = cur.fetchone()
    if not row:
        # por seguridad, si no existe el plan, quota 0
        return 0
    return int(row[0])


def _day_window_mx(now: datetime):
    local = now.astimezone(MX_TZ)
    start = local.replace(hour=0, minute=0, second=0, microsecond=0)
    end = start + timedelta(days=1)
    return start.astimezone(ZoneInfo("UTC")), end.astimezone(ZoneInfo("UTC"))


def count_day_usage(visitor_id: str, user_id: str | None) -> int:
    now = datetime.now(tz=ZoneInfo("UTC"))
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
                    (user_id, start_utc, end_utc)
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
                    (visitor_id, start_utc, end_utc)
                )
            row = cur.fetchone()
    return int(row[0]) if row else 0


def count_period_usage(user_id: str, period_start, period_end) -> int:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM usage_events
                WHERE user_id = %s
                  AND allowed = TRUE
                  AND created_at >= %s AND created_at < %s
                """,
                (user_id, period_start, period_end)
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
):
    event_id = str(uuid4())
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO usage_events(
                  event_id, visitor_id, user_id, profile, plan_code, model_used,
                  endpoint, allowed, reason, created_at
                )
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())
                """,
                (event_id, visitor_id, user_id, profile, plan_code, model_used,
                 endpoint, allowed, reason)
            )
        conn.commit()