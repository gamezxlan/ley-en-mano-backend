# app/billing_portal.py
from __future__ import annotations

from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
import os
import stripe
from stripe.error import InvalidRequestError
from .db import pool
from .routes import _get_session_user_id  # tu helper de cookie session

router = APIRouter(prefix="/billing", tags=["billing-portal"])

stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "http://localhost:5173")

PLAN_TO_PRICE = {
    "p99": os.environ["STRIPE_PRICE_P99"],
    "p199": os.environ["STRIPE_PRICE_P199"],
}

class PortalRequest(BaseModel):
    target_plan: str  # "p199" por ahora


def _get_latest_stripe_customer_id(user_id: str) -> str | None:
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


@router.post("/portal")
def create_portal_session(request: Request, body: dict):
    ...
    # Traemos subscription + item id
    try:
        sub = stripe.Subscription.retrieve(
            stripe_subscription_id,
            expand=["items.data.price"],
        )
    except Exception:
        raise HTTPException(status_code=502, detail="No se pudo leer la suscripción")

    items = (sub.get("items") or {}).get("data") or []
    if not items or not items[0].get("id"):
        raise HTTPException(status_code=409, detail="Suscripción sin item")

    subscription_item_id = items[0]["id"]

    # ✅ Si el price actual ya es el target, no intentes update
    current_price_id = None
    try:
        current_price_id = items[0]["price"]["id"]
    except Exception:
        pass

    if current_price_id == target_price_id:
        raise HTTPException(status_code=409, detail="Ya estás en ese plan.")

    return_url = f"{FRONTEND_BASE_URL}/?billing=ok"

    try:
        portal = stripe.billing_portal.Session.create(
            customer=stripe_customer_id,
            return_url=return_url,
            flow_data={
                "type": "subscription_update",
                "subscription_update": {
                    "subscription": stripe_subscription_id,
                    "items": [{"id": subscription_item_id, "price": target_price_id}],
                },
            },
        )
    except InvalidRequestError as e:
        msg = str(e.user_message or e)
        # ✅ fallback por si stripe responde “no changes” por otras razones
        if "no changes to confirm" in msg.lower():
            raise HTTPException(status_code=409, detail="No hay cambios por aplicar (ya estás en ese plan).")
        raise HTTPException(status_code=502, detail=f"Stripe portal error: {msg}")
    except Exception:
        raise HTTPException(status_code=502, detail="Stripe portal error")

    return {"url": portal.url}