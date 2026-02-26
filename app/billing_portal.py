# app/billing_portal.py
from __future__ import annotations

from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
import os
import stripe
from stripe import error as stripe_error

from .db import pool
from .billing_routes import _get_session_user_id  # usa el que ya tienes ahí

router = APIRouter(prefix="/billing", tags=["billing-portal"])

stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "http://localhost:5173")

PRICE_P99 = os.environ["STRIPE_PRICE_P99"]
PRICE_P199 = os.environ["STRIPE_PRICE_P199"]

PLAN_TO_PRICE = {
    "p99": PRICE_P99,
    "p199": PRICE_P199,
}

class PortalRequest(BaseModel):
    target_plan: str  # "p199" por ahora


def _get_active_stripe_customer_id(user_id: str) -> str | None:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT stripe_customer_id
                FROM subscriptions
                WHERE user_id = %s
                  AND stripe_customer_id IS NOT NULL
                ORDER BY current_period_end DESC, created_at DESC
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
                ORDER BY current_period_end DESC, created_at DESC
                LIMIT 1
                """,
                (user_id,),
            )
            row = cur.fetchone()
            return str(row[0]) if row and row[0] else None


def _get_current_price_id(sub: dict) -> str | None:
    try:
        items = (sub.get("items") or {}).get("data") or []
        if items and items[0].get("price"):
            return items[0]["price"].get("id")
    except Exception:
        pass
    return None


@router.post("/portal")
def create_portal_session(request: Request, body: PortalRequest):
    user_id = _get_session_user_id(request)
    if not user_id:
        raise HTTPException(status_code=401, detail="No autenticado")

    target_plan = (body.target_plan or "").strip().lower()
    if target_plan not in PLAN_TO_PRICE:
        raise HTTPException(status_code=400, detail="target_plan inválido")

    stripe_customer_id = _get_active_stripe_customer_id(user_id)
    stripe_subscription_id = _get_active_stripe_subscription_id(user_id)
    if not stripe_customer_id or not stripe_subscription_id:
        raise HTTPException(status_code=409, detail="No hay suscripción activa para mejorar")

    target_price_id = PLAN_TO_PRICE[target_plan]
    return_url = f"{FRONTEND_BASE_URL}/?billing=ok"

    # Lee la suscripción para obtener subscription_item_id y evitar “no changes”
    try:
        sub = stripe.Subscription.retrieve(stripe_subscription_id, expand=["items.data.price"])
    except Exception:
        raise HTTPException(status_code=502, detail="No se pudo leer la suscripción en Stripe")

    items = (sub.get("items") or {}).get("data") or []
    if not items or not items[0].get("id"):
        raise HTTPException(status_code=409, detail="Suscripción sin item")

    subscription_item_id = items[0]["id"]

    current_price_id = _get_current_price_id(sub)
    if current_price_id == target_price_id:
        # Stripe ya está en ese price
        raise HTTPException(status_code=409, detail="Stripe ya tiene ese plan activo; no hay cambios por confirmar.")

    try:
        portal = stripe.billing_portal.Session.create(
            customer=stripe_customer_id,
            return_url=return_url,
            flow_data={
                "type": "subscription_update",
                "subscription_update": {
                    "subscription": stripe_subscription_id,
                    "items": [
                        {"id": subscription_item_id, "price": target_price_id}
                    ],
                },
            },
        )
    except stripe_error.InvalidRequestError as e:
        # Mensaje útil para debug
        raise HTTPException(status_code=502, detail=f"Stripe portal error: {str(e)}")
    except Exception:
        raise HTTPException(status_code=502, detail="Stripe portal error")

    return {"url": portal.url}