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

# ✅ price_id real -> plan_code (fuente de verdad para upgrades via Portal)
PRICE_TO_PLAN = {
    os.environ.get("STRIPE_PRICE_P99"): "p99",
    os.environ.get("STRIPE_PRICE_P199"): "p199",
}
PRICE_TO_PLAN = {k: v for k, v in PRICE_TO_PLAN.items() if k}


# -----------------------
# Debug helpers
# -----------------------
def _safe(v, maxlen: int = 180):
    try:
        s = str(v)
    except Exception:
        return "<unprintable>"
    if len(s) > maxlen:
        return s[:maxlen] + "..."
    return s

def _debug_db_dump_user(user_id: str):
    """Imprime el top 5 de subs del usuario para detectar 'fila equivocada'."""
    try:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT plan_code, status, stripe_subscription_id, stripe_price_id,
                           current_period_end, created_at
                    FROM subscriptions
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                    LIMIT 5
                    """,
                    (user_id,),
                )
                rows = cur.fetchall() or []
        print("DB TOP5 subs for user:", user_id)
        for r in rows:
            print("  -", r)
    except Exception as e:
        print("DB DUMP USER failed:", type(e).__name__, _safe(e))

def _debug_db_read_sub(stripe_subscription_id: str):
    """Lee y muestra lo que quedó en DB para ese stripe_subscription_id."""
    try:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT user_id, plan_code, status, stripe_subscription_id, stripe_price_id,
                           current_period_start, current_period_end, created_at
                    FROM subscriptions
                    WHERE stripe_subscription_id = %s
                    """,
                    (stripe_subscription_id,),
                )
                row = cur.fetchone()
        print("DB READ sub:", stripe_subscription_id, "=>", row)
    except Exception as e:
        print("DB READ sub failed:", type(e).__name__, _safe(e))


# -----------------------
# Stripe mapping
# -----------------------
def _dt_from_unix(ts: int | None) -> datetime | None:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc)
    except Exception:
        return None

def _get_price_id_from_sub(sub: dict) -> str | None:
    try:
        items = (sub.get("items") or {}).get("data") or []
        if items and items[0].get("price"):
            return items[0]["price"].get("id")
    except Exception:
        pass
    return None

def _resolve_plan_code(sub: dict) -> str | None:
    """
    ✅ IMPORTANTE:
    - En upgrades por Stripe Portal, la metadata 'plan_code' puede quedarse vieja (p99).
    - Por eso: primero resolvemos por price_id real, y solo si no se puede, usamos metadata.
    """
    price_id = _get_price_id_from_sub(sub)
    if price_id and price_id in PRICE_TO_PLAN:
        return PRICE_TO_PLAN[price_id]

    md = sub.get("metadata") or {}
    pc = (md.get("plan_code") or "").strip().lower()
    if pc in ("p99", "p199"):
        return pc

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


# -----------------------
# DB writers
# -----------------------
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
                print("DB deactivate rowcount:", cur.rowcount, "user:", user_id, "keep:", keep_stripe_sub_id)
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
                print("DB deactivate rowcount:", cur.rowcount, "user:", user_id, "keep: None")
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
    - desactiva otras active del mismo user
    - UPSERT por stripe_subscription_id (requiere UNIQUE en stripe_subscription_id)
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
            print(
                "DB UPSERT exec ok:",
                "sub:", stripe_subscription_id,
                "user:", user_id,
                "plan:", plan_code,
                "status:", local_status,
                "price:", stripe_price_id,
            )
        conn.commit()

    # ✅ Confirmación inmediata de lo guardado
    _debug_db_read_sub(stripe_subscription_id)
    _debug_db_dump_user(user_id)


def _update_plan_only_by_stripe_sub(
    *,
    stripe_subscription_id: str,
    plan_code: str,
    local_status: str | None,
    stripe_price_id: str | None,
    stripe_customer_id: str | None,
):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE subscriptions
                SET plan_code = %s,
                    status = COALESCE(%s, status),
                    stripe_price_id = COALESCE(%s, stripe_price_id),
                    stripe_customer_id = COALESCE(%s, stripe_customer_id)
                WHERE stripe_subscription_id = %s
                """,
                (plan_code, local_status, stripe_price_id, stripe_customer_id, stripe_subscription_id),
            )
            print("DB PLAN-ONLY UPDATE rowcount:", cur.rowcount, "sub:", stripe_subscription_id, "plan:", plan_code, "price:", stripe_price_id)
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
            print("DB UPDATE status rowcount:", cur.rowcount, "sub:", stripe_subscription_id, "=>", new_status)
        conn.commit()
    _debug_db_read_sub(stripe_subscription_id)

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
            print("DB UPDATE periods rowcount:", cur.rowcount, "sub:", stripe_subscription_id)
        conn.commit()
    _debug_db_read_sub(stripe_subscription_id)

def _upsert_from_subscription_event(sub: dict, checkout_session_id: str | None = None):
    stripe_subscription_id = sub.get("id")
    stripe_customer_id = sub.get("customer")

    md = sub.get("metadata") or {}
    user_id = (md.get("user_id") or "").strip()

    # Intentamos resolver plan desde el objeto recibido
    plan_code = _resolve_plan_code(sub)
    price_id = _get_price_id_from_sub(sub)
    local_status = _map_stripe_status(sub.get("status"))

    ps = _dt_from_unix(sub.get("current_period_start"))
    pe = _dt_from_unix(sub.get("current_period_end"))

    print(
        "SUB EVENT parsed:",
        "sub:", stripe_subscription_id,
        "user:", user_id,
        "status:", local_status,
        "price_id:", price_id,
        "resolved_plan:", plan_code,
        "periods:", _safe(sub.get("current_period_start")), _safe(sub.get("current_period_end")),
    )

    if not ps or not pe:
        # ✅ Caso real tuyo: Stripe/Portal actualiza price pero tus eventos no traen periodos ni invoice.subscription
        # Como la suscripción YA existe en DB (por la compra inicial), hacemos update parcial.
        print("SUB EVENT: still missing periods -> doing PLAN-ONLY update (keeping DB periods)")
        _update_plan_only_by_stripe_sub(
            stripe_subscription_id=stripe_subscription_id,
            plan_code=plan_code,
            local_status=local_status,
            stripe_price_id=price_id,
            stripe_customer_id=stripe_customer_id,
        )

        # Debug: lee DB para confirmar
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT user_id, plan_code, status, stripe_subscription_id, stripe_price_id,
                        current_period_start, current_period_end, created_at
                    FROM subscriptions
                    WHERE stripe_subscription_id = %s
                    """,
                    (stripe_subscription_id,),
                )
                row = cur.fetchone()
                print("DB READ AFTER PLAN-ONLY:", row)

        return

    _ensure_user_exists(user_id)

    # ✅ Si faltan periodos (te está pasando en upgrades), recuperamos de Stripe
    if not ps or not pe:
        print("SUB EVENT: missing periods -> retrieving from Stripe:", stripe_subscription_id)
        try:
            fresh = stripe.Subscription.retrieve(
                stripe_subscription_id,
                expand=["items.data.price"],
            )
        except Exception as e:
            print("Subscription.retrieve failed:", type(e).__name__, _safe(e))
            return

        # reemplaza sub por el fresco
        sub = fresh
        stripe_customer_id = sub.get("customer") or stripe_customer_id
        local_status = _map_stripe_status(sub.get("status"))

        ps = _dt_from_unix(sub.get("current_period_start"))
        pe = _dt_from_unix(sub.get("current_period_end"))

        # re-resolver plan/price con el objeto fresco
        price_id = _get_price_id_from_sub(sub)
        plan_code = _resolve_plan_code(sub)

        print(
            "SUB EVENT refreshed:",
            "status:", local_status,
            "price_id:", price_id,
            "resolved_plan:", plan_code,
            "periods:", _safe(sub.get("current_period_start")), _safe(sub.get("current_period_end")),
        )

    if not plan_code:
        print("SUB EVENT skip: cannot resolve plan_code even after refresh")
        return

    if not ps or not pe:
        print("SUB EVENT skip: still missing periods after refresh")
        return

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


# -----------------------
# Webhook
# -----------------------
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
    obj = event["data"]["object"]

    print("STRIPE WEBHOOK:", etype)
    print("OBJ.ID:", _safe(obj.get("id")))

    # 1) Suscripción creada/actualizada: UPSERT (crea o actualiza)
    if etype in ("customer.subscription.created", "customer.subscription.updated"):
        sub = obj
        try:
            print("SUB raw:", "id=", _safe(sub.get("id")), "customer=", _safe(sub.get("customer")), "status=", _safe(sub.get("status")))
            print("SUB md:", _safe(sub.get("metadata")))
            print("SUB price_id:", _safe(_get_price_id_from_sub(sub)), "resolved_plan:", _safe(_resolve_plan_code(sub)))

            _upsert_from_subscription_event(sub, checkout_session_id=None)

            print("SUB EVENT handled OK:", _safe(sub.get("id")))
        except Exception as e:
            print("SUB EVENT failed:", type(e).__name__, _safe(e))
        return {"ok": True}

    # 2) Checkout completado (opcional): asegura stripe_checkout_session_id en DB
    if etype == "checkout.session.completed":
        session = obj
        md = session.get("metadata") or {}
        user_id = (md.get("user_id") or "").strip()

        print("checkout.md:", md)
        print("checkout.subscription:", _safe(session.get("subscription")))
        print("checkout.customer:", _safe(session.get("customer")))

        if not user_id:
            print("checkout.session.completed skip: missing user_id")
            return {"ok": True}

        _ensure_user_exists(user_id)

        stripe_checkout_session_id = session.get("id")
        stripe_customer_id = session.get("customer")
        stripe_subscription_id = session.get("subscription")

        if not stripe_subscription_id:
            print("checkout.session.completed skip: missing subscription")
            return {"ok": True}

        try:
            sub = stripe.Subscription.retrieve(
                stripe_subscription_id,
                expand=["latest_invoice.lines.data", "items.data.price"],
            )
        except Exception as e:
            print("Subscription.retrieve failed:", type(e).__name__, _safe(e))
            return {"ok": True}

        ps = _dt_from_unix(sub.get("current_period_start"))
        pe = _dt_from_unix(sub.get("current_period_end"))

        if (not ps or not pe):
            latest_inv = sub.get("latest_invoice")
            if isinstance(latest_inv, dict):
                ps2, pe2 = _periods_from_invoice_object(latest_inv)
                ps = ps or ps2
                pe = pe or pe2

        if not ps or not pe:
            print("checkout.session.completed skip: missing periods even after fallback")
            return {"ok": True}

        plan_code = _resolve_plan_code(sub)
        if not plan_code:
            print("checkout.session.completed skip: cannot resolve plan_code")
            return {"ok": True}

        local_status = _map_stripe_status(sub.get("status"))
        price_id = _get_price_id_from_sub(sub)

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
        print("checkout.session.completed DB UPSERT OK for:", stripe_subscription_id)
        return {"ok": True}

    # 3) Pagos / invoice: asegura periodos y plan_code por price
    if etype in ("invoice.paid", "invoice.payment_succeeded"):
        inv = obj
        stripe_subscription_id = inv.get("subscription")
        stripe_customer_id = inv.get("customer")

        print("INV:", "id=", _safe(inv.get("id")), "sub=", _safe(stripe_subscription_id), "customer=", _safe(stripe_customer_id))

        if not stripe_subscription_id:
            print("invoice skip: missing subscription")
            return {"ok": True}

        try:
            sub = stripe.Subscription.retrieve(
                stripe_subscription_id,
                expand=["items.data.price"],
            )
        except Exception as e:
            print("Subscription.retrieve failed:", type(e).__name__, _safe(e))
            return {"ok": True}

        md = sub.get("metadata") or {}
        user_id = (md.get("user_id") or "").strip()
        if not user_id:
            print("invoice skip: missing user_id in subscription metadata")
            return {"ok": True}

        plan_code = _resolve_plan_code(sub)
        if not plan_code:
            print("invoice skip: cannot resolve plan_code")
            return {"ok": True}

        _ensure_user_exists(user_id)

        ps = _dt_from_unix(sub.get("current_period_start"))
        pe = _dt_from_unix(sub.get("current_period_end"))

        if (not ps or not pe):
            ps2, pe2 = _periods_from_invoice_object(inv)
            ps = ps or ps2
            pe = pe or pe2

        if not ps or not pe:
            print("invoice skip: missing periods even after fallback")
            return {"ok": True}

        local_status = _map_stripe_status(sub.get("status"))
        price_id = _get_price_id_from_sub(sub)

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
        print("invoice DB UPSERT OK for:", stripe_subscription_id)
        return {"ok": True}

    # 4) Pago fallido
    if etype == "invoice.payment_failed":
        inv = obj
        stripe_subscription_id = inv.get("subscription")
        print("invoice.payment_failed sub:", _safe(stripe_subscription_id))
        if stripe_subscription_id:
            _update_subscription_status_by_stripe_sub(stripe_subscription_id, "past_due")
        return {"ok": True}

    # 5) Suscripción eliminada
    if etype == "customer.subscription.deleted":
        sub = obj
        stripe_subscription_id = sub.get("id")
        print("customer.subscription.deleted sub:", _safe(stripe_subscription_id))
        if stripe_subscription_id:
            _update_subscription_status_by_stripe_sub(stripe_subscription_id, "canceled")
        return {"ok": True}

    return {"ok": True}