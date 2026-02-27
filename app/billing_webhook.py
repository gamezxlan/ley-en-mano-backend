# app/billing_webhook.py
from __future__ import annotations

from fastapi import APIRouter, Request, HTTPException
import os
from uuid import uuid4

import stripe
from .db import pool
from .usage_repo import ensure_user

router = APIRouter(prefix="/billing", tags=["billing-webhook"])

stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
WEBHOOK_SECRET = os.environ["STRIPE_WEBHOOK_SECRET"]


def _safe(v, maxlen: int = 180):
    try:
        s = str(v)
    except Exception:
        return "<unprintable>"
    return s if len(s) <= maxlen else (s[:maxlen] + "...")


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

    print("STRIPE WEBHOOK:", etype, "OBJ.ID:", _safe(obj.get("id")))

    if etype != "checkout.session.completed":
        return {"ok": True}

    session = obj
    md = session.get("metadata") or {}
    user_id = (md.get("user_id") or "").strip()

    if not user_id:
        print("checkout.session.completed: missing user_id in metadata")
        return {"ok": True}

    ensure_user(user_id)

    checkout_session_id = session.get("id")
    payment_intent_id = session.get("payment_intent")
    stripe_customer_id = session.get("customer")

    # ✅ Expandimos price.product para poder leer product.metadata
    try:
        full = stripe.checkout.Session.retrieve(
            checkout_session_id,
            expand=["line_items.data.price.product"],
        )
    except Exception as e:
        print("Session.retrieve failed:", type(e).__name__, _safe(e))
        return {"ok": True}

    items = (full.get("line_items") or {}).get("data") or []
    if not items:
        print("checkout.session.completed: no line_items")
        return {"ok": True}

    price = (items[0].get("price") or {})
    price_id = price.get("id")

    # -----------------------------
    # ✅ Metadata: price -> product -> session -> fallback mapping
    # -----------------------------
    price_md = price.get("metadata") or {}

    product = price.get("product")
    product_md = {}
    if isinstance(product, dict):
        product_md = product.get("metadata") or {}

    # Fuente de verdad de respaldo (por si falta metadata en Stripe)
    PLAN_TO_QUOTA = {"p99": 100, "p199": 300}
    PLAN_TO_MONTHS = {"p99": 12, "p199": 12}

    plan_code = (
        price_md.get("plan_code")
        or product_md.get("plan_code")
        or (md.get("plan_code") if isinstance(md, dict) else None)
        or ""
    ).strip().lower()

    if plan_code not in PLAN_TO_QUOTA:
        print("checkout.session.completed: invalid plan_code:", _safe(plan_code))
        print("DEBUG md.plan_code:", _safe(md.get("plan_code") if isinstance(md, dict) else None))
        print("DEBUG price_md.plan_code:", _safe(price_md.get("plan_code")))
        print("DEBUG product_md.plan_code:", _safe(product_md.get("plan_code")))
        return {"ok": True}

    raw_quota = price_md.get("quota_total") or product_md.get("quota_total")
    quota_total = int(raw_quota) if raw_quota else int(PLAN_TO_QUOTA[plan_code])

    raw_months = price_md.get("validity_months") or product_md.get("validity_months")
    validity_months = int(raw_months) if raw_months else int(PLAN_TO_MONTHS[plan_code])

    # Debug útil mientras lo estabilizas
    print(
        "checkout.session.completed resolved:",
        "user:", _safe(user_id),
        "plan:", _safe(plan_code),
        "quota:", quota_total,
        "months:", validity_months,
        "price_id:", _safe(price_id),
    )

    # Insert idempotente (stripe_checkout_session_id es UNIQUE)
    try:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO entitlements(
                      entitlement_id, user_id, plan_code,
                      quota_total, remaining,
                      valid_until,
                      stripe_customer_id,
                      stripe_price_id,
                      stripe_checkout_session_id,
                      stripe_payment_intent_id,
                      status,
                      created_at
                    )
                    VALUES (
                      %s, %s, %s,
                      %s, %s,
                      NOW() + (%s || ' months')::interval,
                      %s, %s, %s, %s,
                      'active',
                      NOW()
                    )
                    ON CONFLICT (stripe_checkout_session_id) DO NOTHING
                    """,
                    (
                        str(uuid4()),
                        user_id,
                        plan_code,
                        quota_total,
                        quota_total,
                        str(validity_months),
                        stripe_customer_id,
                        price_id,
                        checkout_session_id,
                        payment_intent_id,
                    ),
                )
                print(
                    "Entitlement insert rowcount:",
                    cur.rowcount,
                    "user:",
                    user_id,
                    "plan:",
 plan_code,
                    "quota:",
                    quota_total,
                )
            conn.commit()
    except Exception as e:
        print("DB entitlement insert failed:", type(e).__name__, _safe(e))
        return {"ok": True}

    return {"ok": True}