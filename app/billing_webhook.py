# app/billing_webhook.py
from __future__ import annotations

from fastapi import APIRouter, Request, HTTPException
import os
from uuid import uuid4
from datetime import datetime, timezone

import stripe
from .db import pool

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
    - Luego UPSERT por stripe_subscription_id (requiere UNIQUE/EXCLUSION en stripe_subscription_id)
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
                    str(uuid4()),
                    user_id,
                    plan_code,
                    local_status,
                    period_start,
                    period_end,
                    stripe_customer_id,
                    stripe_subscription_id,
                    stripe_price_id,
                    stripe_checkout_session_id,
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


def _update_periods_by_stripe_sub(stripe_subscription_id: str, period_start: datetime, period_end: datetime):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE subscriptions
                SET current_period_start = %s,
                    current_period_end = %s
                WHERE stripe_subscription_id = %s
                """,
                (period_start, period_end, stripe_subscription_id),
            )
        conn.commit()

def _upsert_from_subscription_event(sub: dict, checkout_session_id: str | None = None):
    stripe_subscription_id = sub.get("id")
    stripe_customer_id = sub.get("customer")

    md = sub.get("metadata") or {}
    user_id = (md.get("user_id") or "").strip()
    plan_code = (md.get("plan_code") or "").strip().lower()

    if not user_id or not plan_code or not stripe_subscription_id:
        # sin metadata no podemos asociar
        return

    _ensure_user_exists(user_id)

    local_status = _map_stripe_status(sub.get("status"))

    ps = _dt_from_unix(sub.get("current_period_start"))
    pe = _dt_from_unix(sub.get("current_period_end"))
    if not ps or not pe:
        # si aún no hay periodos, no escribimos (lo rescata invoice.payment_succeeded)
        return

    # price_id
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
        period_start=ps,
        period_end=pe,
        stripe_customer_id=stripe_customer_id,
        stripe_subscription_id=stripe_subscription_id,
        stripe_price_id=price_id,
        stripe_checkout_session_id=checkout_session_id,
    )

def _periods_from_invoice_object(inv: dict) -> tuple[datetime | None, datetime | None]:
    try:
        lines = (inv.get("lines") or {}).get("data") or []
        if lines and lines[0].get("period"):
            ps = _dt_from_unix(lines[0]["period"].get("start"))
            pe = _dt_from_unix(lines[0]["period"].get("end"))
            return ps, pe
    except Exception:
        pass
    return None, None

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

    etype = event.get("type")
    print("STRIPE WEBHOOK:", etype)

    obj = event["data"]["object"]
    print("OBJ.ID:", obj.get("id"))

    # 1) Suscripción creada/actualizada: UPSERT (crea o actualiza)
    if etype in ("customer.subscription.created", "customer.subscription.updated"):
        sub = obj
        try:
            _upsert_from_subscription_event(sub, checkout_session_id=None)
        except Exception as e:
            print("upsert_from_subscription_event failed:", type(e).__name__, str(e)[:200])
        return {"ok": True}

        # ✅ Checkout completado: aquí SÍ tenemos metadata (user_id/plan_code)
    if etype == "checkout.session.completed":
        session = obj
        md = session.get("metadata") or {}
        user_id = (md.get("user_id") or "").strip()
        plan_code = (md.get("plan_code") or "").strip().lower()

        print("checkout.md:", md)
        print("checkout.subscription:", session.get("subscription"))

        if not user_id or not plan_code:
            return {"ok": True}

        _ensure_user_exists(user_id)

        stripe_checkout_session_id = session.get("id")
        stripe_customer_id = session.get("customer")
        stripe_subscription_id = session.get("subscription")

        if not stripe_subscription_id:
            return {"ok": True}

        # Traemos subscription + latest_invoice expandido
        try:
            sub = stripe.Subscription.retrieve(
                stripe_subscription_id,
                expand=["latest_invoice.lines.data", "items.data.price"],
            )
        except Exception as e:
            print("Subscription.retrieve failed:", type(e).__name__, str(e)[:200])
            return {"ok": True}

        ps = _dt_from_unix(sub.get("current_period_start"))
        pe = _dt_from_unix(sub.get("current_period_end"))

        # ✅ fallback: periodos desde latest_invoice
        if (not ps or not pe):
            latest_inv = sub.get("latest_invoice")
            if isinstance(latest_inv, dict):
                ps2, pe2 = _periods_from_invoice_object(latest_inv)
                ps = ps or ps2
                pe = pe or pe2

        print("sub.status:", sub.get("status"))
        print("sub.periods:", sub.get("current_period_start"), sub.get("current_period_end"))
        print("computed periods:", ps, pe)

        if not ps or not pe:
            return {"ok": True}

        local_status = _map_stripe_status(sub.get("status"))

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
            period_start=ps,
            period_end=pe,
            stripe_customer_id=stripe_customer_id,
            stripe_subscription_id=stripe_subscription_id,
            stripe_price_id=price_id,
            stripe_checkout_session_id=stripe_checkout_session_id,
        )
        print("DB UPSERT OK for:", stripe_subscription_id)
        return {"ok": True}

    # 2) Pagos / invoice: asegura periodos (fallback desde invoice.lines)
    if etype in ("invoice.paid", "invoice.payment_succeeded"):
        inv = obj
        stripe_subscription_id = inv.get("subscription")
        stripe_customer_id = inv.get("customer")

        if not stripe_subscription_id:
            return {"ok": True}

        try:
            sub = stripe.Subscription.retrieve(stripe_subscription_id)
        except Exception as e:
            print("Subscription.retrieve failed:", str(e))
            return {"ok": True}

        md = sub.get("metadata") or {}
        user_id = (md.get("user_id") or "").strip()
        plan_code = (md.get("plan_code") or "").strip().lower()

        if not user_id or not plan_code:
            return {"ok": True}

        _ensure_user_exists(user_id)

        ps = _dt_from_unix(sub.get("current_period_start"))
        pe = _dt_from_unix(sub.get("current_period_end"))

        # ✅ Fallback: periodos del invoice
        if (not ps or not pe):
            try:
                lines = (inv.get("lines") or {}).get("data") or []
                if lines and lines[0].get("period"):
                    ps = _dt_from_unix(lines[0]["period"].get("start"))
                    pe = _dt_from_unix(lines[0]["period"].get("end"))
            except Exception:
                pass

        if not ps or not pe:
            return {"ok": True}

        local_status = _map_stripe_status(sub.get("status"))

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
            period_start=ps,
            period_end=pe,
            stripe_customer_id=stripe_customer_id,
            stripe_subscription_id=stripe_subscription_id,
            stripe_price_id=price_id,
            stripe_checkout_session_id=None,
        )
        print("inv.lines:", (inv.get("lines") or {}).get("data")[:1])
        print("sub.current_period_start:", sub.get("current_period_start"))
        print("sub.current_period_end:", sub.get("current_period_end"))
        return {"ok": True}

    # 3) Pago fallido
    if etype == "invoice.payment_failed":
        inv = obj
        stripe_subscription_id = inv.get("subscription")
        if stripe_subscription_id:
            _update_subscription_status_by_stripe_sub(stripe_subscription_id, "past_due")
        return {"ok": True}

    # 4) Suscripción eliminada
    if etype == "customer.subscription.deleted":
        sub = obj
        stripe_subscription_id = sub.get("id")
        if stripe_subscription_id:
            _update_subscription_status_by_stripe_sub(stripe_subscription_id, "canceled")
        return {"ok": True}

    # 5) checkout.session.completed lo puedes manejar o ignorar (ya no es necesario para DB)
    return {"ok": True}