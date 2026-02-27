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

# Cookies/sessions
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

def _get_user_stripe_customer_id(user_id: str) -> str | None:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT stripe_customer_id
                FROM users
                WHERE user_id = %s
                """,
                (user_id,),
            )
            row = cur.fetchone()
    return str(row[0]) if row and row[0] else None

def _save_user_stripe_customer_id(user_id: str, stripe_customer_id: str):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE users
                SET stripe_customer_id = %s
                WHERE user_id = %s
                """,
                (stripe_customer_id, user_id),
            )
        conn.commit()

def _get_or_create_stripe_customer(*, user_id: str, email: str | None) -> str:
    """
    Reutiliza un customer existente (users.stripe_customer_id).
    Si no existe, crea uno nuevo y lo guarda.
    """
    existing = _get_user_stripe_customer_id(user_id)
    if existing:
        return existing

    # Crear customer en Stripe (idempotencia: metadata user_id)
    try:
        customer = stripe.Customer.create(
            email=email if email else None,
            metadata={"user_id": user_id, "app": "leyenmano"},
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Stripe customer error: {type(e).__name__}")

    cid = customer.get("id")
    if not cid:
        raise HTTPException(status_code=502, detail="Stripe customer creation failed (no id)")

    _save_user_stripe_customer_id(user_id, cid)
    return str(cid)

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

    # ✅ Customer real (evita que Stripe cree "Invitado")
    stripe_customer_id = _get_or_create_stripe_customer(user_id=user_id, email=email)

    success_url = f"{FRONTEND_BASE_URL}/?billing=ok"
    cancel_url = f"{FRONTEND_BASE_URL}/?billing=cancel"

    try:
        session = stripe.checkout.Session.create(
            mode="payment",
            line_items=[{"price": price_id, "quantity": 1}],
            success_url=success_url,
            cancel_url=cancel_url,

            # ✅ Vincula el pago a un Customer real
            customer=stripe_customer_id,

            # (opcional) fuerza que Checkout use el customer y no haga cosas raras
            customer_update={
                "address": "auto",
                "name": "auto",
            },

            client_reference_id=user_id,

            # ✅ metadata en session (para webhook)
            metadata={
                "user_id": user_id,
                "plan_code": plan_code,
                "app": "leyenmano",
                "billing_type": "one_time",
            },
        )
    except Exception as e:
        print("Stripe checkout error:", type(e).__name__, str(e))
        raise HTTPException(status_code=502, detail=f"Stripe error: {type(e).__name__}")

    return {"url": session.url}