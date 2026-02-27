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

    # Traer line_items con price expandido para leer price.metadata
    try:
        full = stripe.checkout.Session.retrieve(
            checkout_session_id,
            expand=["line_items.data.price"],
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
    price_md = price.get("metadata") or {}

    plan_code = (price_md.get("plan_code") or md.get("plan_code") or "").strip().lower()
    quota_total = int(price_md.get("quota_total") or 0)
    validity_months = int(price_md.get("validity_months") or 12)

    if plan_code not in ("p99", "p199"):
        print("checkout.session.completed: invalid plan_code:", _safe(plan_code))
        return {"ok": True}

    if quota_total <= 0:
        print("checkout.session.completed: missing quota_total in price.metadata")
        return {"ok": True}

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
                print("Entitlement insert rowcount:", cur.rowcount, "user:", user_id, "plan:", plan_code, "quota:", quota_total)
            conn.commit()
    except Exception as e:
        print("DB entitlement insert failed:", type(e).__name__, _safe(e))
        return {"ok": True}

    return {"ok": True}