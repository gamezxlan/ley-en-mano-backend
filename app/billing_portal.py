# app/billing_portal.py
from __future__ import annotations
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
import os
import stripe
from .db import pool
from .routes import _get_session_user_id

router = APIRouter(prefix="/billing", tags=["billing-portal"])

stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "http://localhost:5173")

PRICE_BY_PLAN = {
    "p99": os.environ["STRIPE_PRICE_P99"],
    "p199": os.environ["STRIPE_PRICE_P199"],
}

class PortalRequest(BaseModel):
    target_plan: str  # "p199" for now

def _get_active_stripe_customer_id(user_id: str) -> str | None:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT stripe_customer_id
                FROM subscriptions
                WHERE user_id = %s
                  AND stripe_customer_id IS NOT NULL
                ORDER BY current_period_end DESC NULLS LAST, created_at DESC
                LIMIT 1
                """,
                (user_id,),
            )
            row = cur.fetchone()
            return str(row[0]) if row and row[0] else None

def _get_active_stripe_subscription_id(user_id: str) -> str | None:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT stripe_subscription_id
                FROM subscriptions
                WHERE user_id = %s
                  AND status = 'active'
                  AND stripe_subscription_id IS NOT NULL
                ORDER BY current_period_end DESC NULLS LAST, created_at DESC
                LIMIT 1
                """,
                (user_id,),
            )
            row = cur.fetchone()
            return str(row[0]) if row and row[0] else None

@router.post("/portal")
def create_portal_session(request: Request, body: PortalRequest):
    user_id = _get_session_user_id(request)
    if not user_id:
        raise HTTPException(status_code=401, detail="No autenticado")

    target = (body.target_plan or "").strip().lower()
    if target not in PRICE_BY_PLAN:
        raise HTTPException(status_code=400, detail="target_plan inválido")

    # Necesitamos customer + subscription para poder “abrir directamente” el upgrade con prorrateo.
    stripe_customer_id = _get_active_stripe_customer_id(user_id)
    stripe_subscription_id = _get_active_stripe_subscription_id(user_id)

    if not stripe_customer_id or not stripe_subscription_id:
        raise HTTPException(status_code=409, detail="No hay suscripción activa para mejorar")

    target_price_id = PRICE_BY_PLAN[target]

    # Stripe necesita el subscription_item id (el item actual) para cambiar el price
    try:
        sub = stripe.Subscription.retrieve(stripe_subscription_id, expand=["items.data"])
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Stripe error: {type(e).__name__}")

    items = (sub.get("items") or {}).get("data") or []
    if not items:
        raise HTTPException(status_code=409, detail="Suscripción sin items")

    subscription_item_id = items[0].get("id")
    if not subscription_item_id:
        raise HTTPException(status_code=409, detail="Suscripción sin item id")

    # Return URL: a dónde vuelve Stripe portal
    return_url = f"{FRONTEND_BASE_URL}/?billing=ok"

    # ✅ Portal con “flow_data” para abrir directo en update_subscription con el nuevo price
    try:
        ps = stripe.billing_portal.Session.create(
            customer=stripe_customer_id,
            return_url=return_url,
            flow_data={
                "type": "subscription_update",
                "subscription_update": {
                    "subscription": stripe_subscription_id,
                    "items": [
                        {
                            "id": subscription_item_id,
                            "price": target_price_id,
                        }
                    ],
                },
            },
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Stripe error: {type(e).__name__}")

    return {"url": ps.url}