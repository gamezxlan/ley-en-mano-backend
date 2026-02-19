# app/policy_service.py
from dataclasses import dataclass
from datetime import datetime
from zoneinfo import ZoneInfo
from .usage_repo import (
    get_active_subscription,
    get_plan_quota,
    count_day_usage,
    count_period_usage,
    MX_TZ,
)

UTC = ZoneInfo("UTC")


@dataclass
class Policy:
    profile: str                 # 'guest' | 'free' | 'premium'
    model_kind: str              # 'lite' | 'flash'
    response_mode: str           # 'blindaje_only' | 'diagnostico_y_blindaje' | 'full'
    cards_per_step: str          # '1' | '2' | 'full'
    daily_limit: int | None
    monthly_limit: int | None
    remaining: int
    reset_at_iso: str
    plan_code: str | None


def _reset_at_daily_iso():
    now = datetime.now(tz=UTC).astimezone(MX_TZ)
    tomorrow = now.replace(hour=0, minute=0, second=0, microsecond=0)
    # si ya es medianoche exacta, igual sumamos 1 día para evitar 0
    if now >= tomorrow:
        from datetime import timedelta
        tomorrow = tomorrow + timedelta(days=1)
    return tomorrow.isoformat()


def build_policy(visitor_id: str, user_id: str | None) -> Policy:
    # Premium si hay subs activa
    if user_id:
        sub = get_active_subscription(user_id)
        if sub:
            plan_code = sub["plan_code"]
            quota = get_plan_quota(plan_code)
            used = count_period_usage(user_id, sub["current_period_start"], sub["current_period_end"])
            remaining = max(0, quota - used)
            return Policy(
                profile="premium",
                model_kind="flash",
                response_mode="full",
                cards_per_step="full",
                daily_limit=None,
                monthly_limit=quota,
                remaining=remaining,
                reset_at_iso=sub["current_period_end"].astimezone(MX_TZ).isoformat(),
                plan_code=plan_code,
            )

        # Registrado sin plan
        used = count_day_usage(visitor_id, user_id)
        limit = 3
        remaining = max(0, limit - used)
        return Policy(
            profile="free",
            model_kind="lite",
            response_mode="diagnostico_y_blindaje",
            cards_per_step="2",
            daily_limit=limit,
            monthly_limit=None,
            remaining=remaining,
            reset_at_iso=_reset_at_daily_iso(),
            plan_code=None,
        )

    # Guest
    used = count_day_usage(visitor_id, None)
    limit = 2
    remaining = max(0, limit - used)
    return Policy(
        profile="guest",
        model_kind="lite",
        response_mode="blindaje_only",
        cards_per_step="1",
        daily_limit=limit,
        monthly_limit=None,
        remaining=remaining,
        reset_at_iso=_reset_at_daily_iso(),
        plan_code=None,
    )