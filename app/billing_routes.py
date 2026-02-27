# app/billing_routes.py
from __future__ import annotations

from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
import os
import hashlib

import stripe

from .db import pool

router = APIRouter(prefix="/billing", tags=["billing"])

# -----------------------
# Stripe init
# -----------------------
stripe.api_key = os.environ["STRIPE_SECRET_KEY"]

FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "http://localhost:5173")

# Cookies/sessions (mismo esquema que ya usas)
ENV = os.getenv("ENV", "development")
COOKIE_DOMAIN = os.getenv("COOKIE_DOMAIN", ".leyenmano.com" if ENV == "production" else None)
SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "session_id")
SESSION_PEPPER = os.getenv("SESSION_PEPPER", "")

PRICE_P99 = os.environ["STRIPE_PRICE_P99"]
PRICE_P199 = os.environ["STRIPE_PRICE_P199"]

PLAN_TO_PRICE = {
    "p99": PRICE_P99,
    "p199": PRICE_P199,
}

# -----------------------
# Helpers
# -----------------------
def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _session_hash(session_id: str) -> str:
    base = f"{SESSION_PEPPER}:{session_id}" if SESSION_PEPPER else session_id
    return _sha256_hex(base)

def _get_cookie(request: Request, key: str) -> str | None:
    v = request.cookies.get(key)
    if not v:
        return None
    v = str(v).strip()
    return v or None

def _get_session_user_id(request: Request) -> str | None:
    sid = _get_cookie(request, SESSION_COOKIE_NAME)
    if not sid:
        return None

    sid_hash = _session_hash(sid)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT user_id
                FROM sessions
                WHERE session_id_hash = %s
                  AND revoked_at IS NULL
                  AND expires_at > NOW()
                """,
                (sid_hash,),
            )
            row = cur.fetchone()
    return str(row[0]) if row else None

def _get_user_email(user_id: str) -> str | None:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT email FROM users WHERE user_id = %s", (user_id,))
            row = cur.fetchone()
    if not row:
        return None
    return str(row[0]) if row[0] else None


# -----------------------
# API
# -----------------------
class CheckoutRequest(BaseModel):
    plan_code: str  # "p99" | "p199"


@router.post("/checkout")
def create_checkout_session(request: Request, body: CheckoutRequest):
    # ✅ Solo cookie session; NO aceptamos user_id del body
    user_id = _get_session_user_id(request)
    if not user_id:
        raise HTTPException(status_code=401, detail="No autenticado")

    plan_code = (body.plan_code or "").strip().lower()
    if plan_code not in PLAN_TO_PRICE:
        raise HTTPException(status_code=400, detail="plan_code inválido")

    price_id = PLAN_TO_PRICE[plan_code]
    email = _get_user_email(user_id)

    # URLs
    # (puedes cambiar query params a lo que quieras en el frontend)
    success_url = f"{FRONTEND_BASE_URL}/?billing=ok"
    cancel_url = f"{FRONTEND_BASE_URL}/?billing=cancel"

    try:
        session = stripe.checkout.Session.create(
            mode="payment",
            line_items=[{"price": price_id, "quantity": 1}],
            success_url=success_url,
            cancel_url=cancel_url,
            customer_email=email if email else None,
            client_reference_id=user_id,

            # si NO quieres cupones/códigos:
            # allow_promotion_codes=False,

            # ✅ metadata en session (para webhook)
            metadata={
                "user_id": user_id,
                "plan_code": plan_code,
                "app": "leyenmano",
                "billing_type": "one_time",
            },
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Stripe error: {type(e).__name__}")

    return {"url": session.url}