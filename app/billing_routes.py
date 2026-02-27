# app/billing_routes.py
from __future__ import annotations

from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
import os
import hashlib
from .usage_repo import get_active_entitlement
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

def _get_plan_row(plan_code: str):
    """
    Lee el plan desde Postgres: plans(plan_code, annual_quota, price_mxn, stripe_price_id)
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT plan_code, annual_quota, price_mxn, stripe_price_id
                FROM plans
                WHERE plan_code = %s
                LIMIT 1
                """,
                (plan_code,),
            )
            row = cur.fetchone()

    if not row:
        return None

    return {
        "plan_code": str(row[0]),
        "annual_quota": int(row[1]) if row[1] is not None else None,
        "price_mxn": int(row[2]) if row[2] is not None else None,
        "stripe_price_id": str(row[3]) if row[3] else None,
    }


def _mxn_to_cents(mxn: int) -> int:
    return int(max(0, mxn)) * 100


def _create_one_time_coupon(*, amount_off_mxn: int, user_id: str, from_entitlement_id: str) -> str:
    """
    Cupón de 1 uso para aplicar crédito del upgrade.
    """
    cents = _mxn_to_cents(amount_off_mxn)
    if cents <= 0:
        raise HTTPException(status_code=400, detail="No hay crédito para aplicar")

    try:
        coupon = stripe.Coupon.create(
            amount_off=cents,
            currency="mxn",
            duration="once",
            max_redemptions=1,
            name="Crédito por upgrade",
            # opcional: que caduque rápido
            # redeem_by=int(time.time()) + 60*30,
            metadata={
                "app": "leyenmano",
                "user_id": user_id,
                "from_entitlement_id": from_entitlement_id,
                "kind": "upgrade_credit",
            },
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Stripe coupon error: {type(e).__name__}: {str(e)[:180]}")

    return str(coupon["id"])

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
        conn.commit()  # ✅ IMPORTANTE

def _get_or_create_stripe_customer(*, user_id: str, email: str | None) -> str:
    existing = _get_user_stripe_customer_id(user_id)

    if existing:
        existing = str(existing).strip().strip("'").strip('"')  # por si guardaste con comillas
        try:
            stripe.Customer.retrieve(existing)
            return existing
        except Exception as e:
            msg = str(e) or ""
            print("Stripe customer retrieve error:", type(e).__name__, msg[:240])

            # ✅ Autocura si no existe (test/live cruzado o borrado)
            if "No such customer" not in msg and "no such customer" not in msg.lower():
                # Si quieres, puedes autocurar SIEMPRE ante cualquier error,
                # pero aquí lo dejamos específico
                pass
            else:
                print("Stripe customer invalid -> recreating:", existing)

    # Crear customer nuevo
    try:
        customer = stripe.Customer.create(
            email=email if email else None,
            metadata={"user_id": user_id, "app": "leyenmano"},
        )
    except Exception as e:
        raise HTTPException(
            status_code=502,
            detail=f"Stripe customer error: {type(e).__name__}: {str(e)[:220]}",
        )

    cid = customer.get("id")
    if not cid:
        raise HTTPException(status_code=502, detail="Stripe customer creation failed (no id)")

    _save_user_stripe_customer_id(user_id, str(cid))
    print("Stripe customer created and saved:", str(cid), "for user:", user_id)
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

    # ✅ Customer real (autocurable)
    stripe_customer_id = _get_or_create_stripe_customer(user_id=user_id, email=email)
    print("USING STRIPE CUSTOMER:", stripe_customer_id, "user:", user_id, "plan:", plan_code)

    success_url = f"{FRONTEND_BASE_URL}/?billing=ok"
    cancel_url = f"{FRONTEND_BASE_URL}/?billing=cancel"

    try:
        session = stripe.checkout.Session.create(
            mode="payment",
            customer=stripe_customer_id,  # ✅ Fuente de verdad
            line_items=[{"price": price_id, "quantity": 1}],
            success_url=success_url,
            cancel_url=cancel_url,
            client_reference_id=user_id,
            metadata={
                "user_id": user_id,
                "plan_code": plan_code,
                "app": "leyenmano",
                "billing_type": "one_time",
            },
        )
    except Exception as e:
        print("Stripe checkout error:", type(e).__name__, str(e))
        raise HTTPException(status_code=502, detail=f"Stripe error: {type(e).__name__}: {str(e)[:220]}")

    return {"url": session.url}