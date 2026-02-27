# app/policy_service.py
from dataclasses import dataclass
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from .usage_repo import (
    get_active_entitlement,
    count_day_usage,
    count_day_usage_by_ip,
    MX_TZ,
)

UTC = ZoneInfo("UTC")


@dataclass
class Policy:
    profile: str                 # 'guest' | 'free' | 'premium'
    tier: str                    # 'premium_basic' | 'premium_full' | 'free' | 'guest'
    model_kind: str              # 'lite' | 'flash'
    response_mode: str           # 'blindaje_only' | 'diagnostico_y_blindaje' | 'full' | 'full_basic'
    cards_per_step: str          # '1' | '2' | 'full'
    daily_limit: int | None
    monthly_limit: int | None
    remaining: int
    reset_at_iso: str
    plan_code: str | None
    subscription_status: str | None = None
    subscription_start_iso: str | None = None
    subscription_end_iso: str | None = None


def _reset_at_daily_iso() -> str:
    now = datetime.now(tz=UTC).astimezone(MX_TZ)
    tomorrow = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if now >= tomorrow:
        tomorrow = tomorrow + timedelta(days=1)
    return tomorrow.isoformat()


def build_policy(visitor_id: str, user_id: str | None, ip_hash: str | None) -> Policy:
    # ------------------------------------------------------
    # PREMIUM: basado en entitlements
    # ------------------------------------------------------
    if user_id:
        ent = get_active_entitlement(user_id)
        if ent:
            plan_code = ent["plan_code"]
            quota = ent["quota_total"]
            remaining = ent["remaining"]
            start_iso = ent["created_at"].astimezone(MX_TZ).isoformat()
            end_iso = ent["valid_until"].astimezone(MX_TZ).isoformat()
            status = ent.get("status")

            if plan_code == "p99":
                return Policy(
                    profile="premium",
                    tier="premium_basic",
                    model_kind="flash",
                    response_mode="full_basic",
                    cards_per_step="full",
                    daily_limit=None,
                    monthly_limit=quota,
                    remaining=remaining,
                    reset_at_iso=end_iso,
                    plan_code=plan_code,
                    subscription_status=status,
                    subscription_start_iso=start_iso,
                    subscription_end_iso=end_iso,
                )

            return Policy(
                profile="premium",
                tier="premium_full",
                model_kind="flash",
                response_mode="full",
                cards_per_step="full",
                daily_limit=None,
                monthly_limit=quota,
                remaining=remaining,
                reset_at_iso=end_iso,
                plan_code=plan_code,
                subscription_status=status,
                subscription_start_iso=start_iso,
                subscription_end_iso=end_iso,
            )

        # ------------------------------------------------------
        # Registrado sin plan => FREE
        # ------------------------------------------------------
        used = count_day_usage(visitor_id, user_id)  # ✅ por usuario
        limit = 2
        remaining = max(0, limit - used)
        return Policy(
            profile="free",
            tier="free",
            model_kind="lite",
            response_mode="diagnostico_y_blindaje",
            cards_per_step="1",
            daily_limit=limit,
            monthly_limit=None,
            remaining=remaining,
            reset_at_iso=_reset_at_daily_iso(),
            plan_code=None,
            subscription_status=None,
            subscription_start_iso=None,
            subscription_end_iso=None,
        )

    # ------------------------------------------------------
    # Guest
    # ------------------------------------------------------
    used = count_day_usage_by_ip(ip_hash) if ip_hash else count_day_usage(visitor_id, None)
    limit = 1
    remaining = max(0, limit - used)
    return Policy(
        profile="guest",
        tier="guest",
        model_kind="lite",
        response_mode="blindaje_only",
        cards_per_step="1",
        daily_limit=limit,
        monthly_limit=None,
        remaining=remaining,
        reset_at_iso=_reset_at_daily_iso(),
        plan_code=None,
        subscription_status=None,
        subscription_start_iso=None,
        subscription_end_iso=None,
    )