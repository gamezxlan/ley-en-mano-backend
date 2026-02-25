# app/billing_webhook.py
from __future__ import annotations

from fastapi import APIRouter, Request, HTTPException
import os
from uuid import uuid4
from datetime import datetime, timezone

import stripe
from .db import pool

etype = event["type"]
print("STRIPE WEBHOOK:", etype)

if etype == "checkout.session.completed":
    session = event["data"]["object"]
    print("session.id:", session.get("id"))
    print("session.subscription:", session.get("subscription"))
    print("session.customer:", session.get("customer"))
    print("metadata:", session.get("metadata"))

router = APIRouter(prefix="/billing", tags=["billing-webhook"])

stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
WEBHOOK_SECRET = os.environ["STRIPE_WEBHOOK_SECRET"]

def _dt_from_unix(ts: int | None) -> datetime | None:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc)
    except Exception:
        return None

def _ensure_user_exists(user_id: str):
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

def _map_stripe_status(s: str | None) -> str:
    st = (s or "").lower().strip()
    if st in ("active", "trialing"):
        return "active"
    if st in ("past_due", "unpaid"):
        return "past_due"
    if st in ("canceled", "cancelled"):
        return "canceled"
    if st in ("incomplete_expired",):
        return "expired"
    if st in ("incomplete",):
        return "incomplete"
    if not st:
        return "active"
    return st

def _deactivate_other_active_subs(user_id: str, keep_stripe_sub_id: str | None):
    # para respetar tu índice ux_one_active_sub_per_user
    with pool.connection() as conn:
        with conn.cursor() as cur:
            if keep_stripe_sub_id:
                cur.execute(
                    """
                    UPDATE subscriptions
                    SET status = 'replaced'
                    WHERE user_id = %s
                      AND status = 'active'
                      AND (stripe_subscription_id IS NULL OR stripe_subscription_id <> %s)
                    """,
                    (user_id, keep_stripe_sub_id),
                )
            else:
                cur.execute(
                    """
                    UPDATE subscriptions
                    SET status = 'replaced'
                    WHERE user_id = %s
                      AND status = 'active'
                    """,
                    (user_id,),
                )
        conn.commit()

def _upsert_subscription_from_stripe(
    *,
    user_id: str,
    plan_code: str,
    local_status: str,
    period_start: datetime,
    period_end: datetime,
    stripe_customer_id: str | None,
    stripe_subscription_id: str,
    stripe_price_id: str | None,
    stripe_checkout_session_id: str | None,
):
    """
    Idempotente:
    - Primero “desactiva” otras active del mismo user (para no violar ux_one_active_sub_per_user)
    - Luego UPSERT por stripe_subscription_id (tu ux_subs_stripe_subscription lo soporta)
    """
    _deactivate_other_active_subs(user_id, stripe_subscription_id)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO subscriptions(
                  subscription_id, user_id, plan_code, status,
                  current_period_start, current_period_end, created_at,
                  stripe_customer_id, stripe_subscription_id, stripe_price_id, stripe_checkout_session_id
                )
                VALUES (%s, %s, %s, %s, %s, %s, NOW(), %s, %s, %s, %s)
                ON CONFLICT (stripe_subscription_id)
                DO UPDATE SET
                  user_id = EXCLUDED.user_id,
                  plan_code = EXCLUDED.plan_code,
                  status = EXCLUDED.status,
                  current_period_start = EXCLUDED.current_period_start,
                  current_period_end = EXCLUDED.current_period_end,
                  stripe_customer_id = COALESCE(EXCLUDED.stripe_customer_id, subscriptions.stripe_customer_id),
                  stripe_price_id = COALESCE(EXCLUDED.stripe_price_id, subscriptions.stripe_price_id),
                  stripe_checkout_session_id = COALESCE(EXCLUDED.stripe_checkout_session_id, subscriptions.stripe_checkout_session_id)
                """,
                (
                    str(uuid4()), user_id, plan_code, local_status,
                    period_start, period_end,
                    stripe_customer_id, stripe_subscription_id, stripe_price_id, stripe_checkout_session_id
                ),
            )
        conn.commit()

def _update_subscription_status_by_stripe_sub(stripe_subscription_id: str, new_status: str):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE subscriptions
                SET status = %s
                WHERE stripe_subscription_id = %s
                """,
                (new_status, stripe_subscription_id),
            )
        conn.commit()

@router.post("/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig = request.headers.get("stripe-signature")
    if not sig:
        raise HTTPException(status_code=400, detail="Missing Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=sig,
            secret=WEBHOOK_SECRET,
        )
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid webhook signature")

    etype = event["type"]

    # 1) Checkout completado
    if etype == "checkout.session.completed":
        session = event["data"]["object"]
        md = session.get("metadata") or {}
        user_id = (md.get("user_id") or "").strip()
        plan_code = (md.get("plan_code") or "").strip().lower()

        if not user_id or not plan_code:
            return {"ok": True}

        _ensure_user_exists(user_id)

        stripe_checkout_session_id = session.get("id")
        stripe_customer_id = session.get("customer")
        stripe_subscription_id = session.get("subscription")

        if not stripe_subscription_id:
            return {"ok": True}

        try:
            sub = stripe.Subscription.retrieve(stripe_subscription_id)
            print("sub.status:", sub.get("status"))
            print("sub.current_period_start:", sub.get("current_period_start"))
            print("sub.current_period_end:", sub.get("current_period_end"))
            period_start = _dt_from_unix(sub.get("current_period_start"))
            period_end = _dt_from_unix(sub.get("current_period_end"))

            if not period_start or not period_end:
                # 👇 NO escribas en DB si Stripe no da periodo real
                return {"ok": True}
        except Exception:
            return {"ok": True}

        period_start = _dt_from_unix(sub.get("current_period_start"))
        period_end = _dt_from_unix(sub.get("current_period_end"))
        local_status = _map_stripe_status(sub.get("status"))

        # price_id: viene en items.data[0].price.id normalmente
        price_id = None
        try:
            items = (sub.get("items") or {}).get("data") or []
            if items and items[0].get("price"):
                price_id = items[0]["price"].get("id")
        except Exception:
            pass

        _upsert_subscription_from_stripe(
            user_id=user_id,
            plan_code=plan_code,
            local_status=local_status,
            period_start=period_start,
            period_end=period_end,
            stripe_customer_id=stripe_customer_id,
            stripe_subscription_id=stripe_subscription_id,
            stripe_price_id=price_id,
            stripe_checkout_session_id=stripe_checkout_session_id,
        )
        return {"ok": True}

    # 2) Cambios de suscripción (recomendado)
    if etype == "customer.subscription.updated":
        sub = event["data"]["object"]
        stripe_subscription_id = sub.get("id")
        if stripe_subscription_id:
            local_status = _map_stripe_status(sub.get("status"))
            _update_subscription_status_by_stripe_sub(stripe_subscription_id, local_status)
        return {"ok": True}

    # 3) Pago fallido
    if etype == "invoice.payment_failed":
        inv = event["data"]["object"]
        stripe_subscription_id = inv.get("subscription")
        if stripe_subscription_id:
            _update_subscription_status_by_stripe_sub(stripe_subscription_id, "past_due")
        return {"ok": True}

    # 4) Suscripción eliminada
    if etype == "customer.subscription.deleted":
        sub = event["data"]["object"]
        stripe_subscription_id = sub.get("id")
        if stripe_subscription_id:
            _update_subscription_status_by_stripe_sub(stripe_subscription_id, "canceled")
        return {"ok": True}

    return {"ok": True}