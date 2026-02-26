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
def create_portal_session(request: Request, body: PortalRequest):
    # 🔐 auth
    user_id = _get_session_user_id(request)
    if not user_id:
        raise HTTPException(status_code=401, detail="No autenticado")

    target_plan = (body.target_plan or "").strip().lower()
    if target_plan not in PRICE_BY_PLAN:
        raise HTTPException(status_code=400, detail="target_plan inválido")

    stripe_customer_id = _get_latest_stripe_customer_id(user_id)
    stripe_subscription_id = _get_active_stripe_subscription_id(user_id)

    # logs útiles en Railway
    print("PORTAL user_id:", user_id)
    print("PORTAL target_plan:", target_plan)
    print("PORTAL stripe_customer_id:", stripe_customer_id)
    print("PORTAL stripe_subscription_id:", stripe_subscription_id)

    if not stripe_customer_id:
        raise HTTPException(status_code=409, detail="No se encontró stripe_customer_id en subscriptions")
    if not stripe_subscription_id:
        raise HTTPException(status_code=409, detail="No hay suscripción activa para mejorar")

    target_price_id = PRICE_BY_PLAN[target_plan]
    return_url = f"{FRONTEND_BASE_URL}/?billing=ok"

    try:
        # 1) Traer subscription y su item id
        sub = stripe.Subscription.retrieve(
            stripe_subscription_id,
            expand=["items.data.price"],
        )

        items = (sub.get("items") or {}).get("data") or []
        if not items or not items[0].get("id"):
            raise HTTPException(status_code=409, detail="Suscripción sin subscription item")

        subscription_item_id = items[0]["id"]

        # 2) Crear portal session en modo subscription_update
        # Stripe aquí calcula prorrateo automáticamente según tu configuración de proration
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

        return {"url": portal.url}

    except HTTPException:
        raise

    except stripe.error.StripeError as e:
        print("STRIPE PORTAL ERROR:", type(e).__name__, str(e))
        raise HTTPException(
            status_code=502,
            detail=f"Stripe error: {type(e).__name__}: {str(e)[:220]}",
        )

    except Exception as e:
        print("PORTAL UNHANDLED ERROR:", type(e).__name__, repr(e))
        raise HTTPException(
            status_code=500,
            detail=f"Server error: {type(e).__name__}: {str(e)[:220]}",
        )