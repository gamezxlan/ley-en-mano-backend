# app/upgrade_checkout.py
from __future__ import annotations

from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
import os
import time
import hashlib

import stripe

from .db import pool
from .usage_repo import get_active_entitlement


router = APIRouter(prefix="/billing", tags=["billing-upgrade"])

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

# Stripe price IDs (fallback)
PRICE_P99 = os.environ.get("STRIPE_PRICE_P99")
PRICE_P199 = os.environ.get("STRIPE_PRICE_P199")

PLAN_TO_PRICE = {
    "p99": PRICE_P99,
    "p199": PRICE_P199,
}

# -----------------------
# Helpers (copiados/compatibles con billing_routes.py)
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
    existing = _get_user_stripe_customer_id(user_id)

    if existing:
        existing = str(existing).strip().strip("'").strip('"')
        try:
            stripe.Customer.retrieve(existing)
            return existing
        except Exception as e:
            msg = str(e) or ""
            print("Stripe customer retrieve error:", type(e).__name__, msg[:240])
            # si no existe, recrea
            if "No such customer" in msg or "no such customer" in msg.lower():
                print("Stripe customer invalid -> recreating:", existing)

    customer = stripe.Customer.create(
        email=email if email else None,
        metadata={"user_id": user_id, "app": "leyenmano"},
    )
    cid = customer.get("id")
    if not cid:
        raise HTTPException(status_code=502, detail="Stripe customer creation failed (no id)")

    _save_user_stripe_customer_id(user_id, str(cid))
    print("Stripe customer created and saved:", str(cid), "for user:", user_id)
    return str(cid)

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
    ✅ max_redemptions=1
    ✅ duration="once"
    ✅ (opcional) redeem_by para que no quede vivo mucho tiempo
    """
    cents = _mxn_to_cents(amount_off_mxn)
    if cents <= 0:
        raise HTTPException(status_code=400, detail="No hay crédito para aplicar")

    # expira en 30 min (puedes ajustar). Evita cupones “colgados”.
    redeem_by = int(time.time()) + 60 * 30

    try:
        coupon = stripe.Coupon.create(
            amount_off=cents,
            currency="mxn",
            duration="once",
            max_redemptions=1,
            redeem_by=redeem_by,
            name="Crédito por upgrade",
            metadata={
                "app": "leyenmano",
                "user_id": user_id,
                "from_entitlement_id": from_entitlement_id,
                "kind": "upgrade_credit",
            },
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Stripe coupon error: {type(e).__name__}: {str(e)[:180]}")

    cid = coupon.get("id")
    if not cid:
        raise HTTPException(status_code=502, detail="Stripe coupon create failed (no id)")

    return str(cid)

# -----------------------
# API
# -----------------------
class UpgradeCheckoutRequest(BaseModel):
    to_plan_code: str  # "p199" (por ahora)

@router.post("/upgrade_checkout")
def create_upgrade_checkout_session(request: Request, body: UpgradeCheckoutRequest):
    """
    Upgrade p99 -> p199 con crédito por consultas restantes.
    - Lee planes desde Postgres (plans)
    - Aplica cupón por crédito (1 uso)
    - En webhook: creas entitlement p199 y marcas el p99 como expired
    """
    user_id = _get_session_user_id(request)
    if not user_id:
        raise HTTPException(status_code=401, detail="No autenticado")

    to_plan = (body.to_plan_code or "").strip().lower()
    if to_plan != "p199":
        raise HTTPException(status_code=400, detail="upgrade solo soporta to_plan_code='p199' por ahora")

    # 1) Debe existir entitlement premium ACTIVO usable (por ahora: p99)
    ent = get_active_entitlement(user_id)
    if not ent:
        raise HTTPException(status_code=400, detail="No tienes un plan activo para hacer upgrade")

    from_plan = str(ent.get("plan_code") or "").strip().lower()
    if from_plan != "p99":
        raise HTTPException(status_code=400, detail=f"Upgrade solo soporta desde p99. Actual: {from_plan}")

    from_entitlement_id = str(ent["entitlement_id"])
    remaining = int(ent["remaining"])
    quota_total = int(ent["quota_total"])

    # 2) Leer planes desde DB
    from_plan_row = _get_plan_row(from_plan)
    to_plan_row = _get_plan_row(to_plan)
    if not from_plan_row or not to_plan_row:
        raise HTTPException(status_code=500, detail="No pude leer plans desde DB")

    from_price_mxn = from_plan_row.get("price_mxn")
    to_price_mxn = to_plan_row.get("price_mxn")
    if from_price_mxn is None or to_price_mxn is None:
        raise HTTPException(status_code=500, detail="Plan sin price_mxn en DB")

    # 3) Stripe price destino (preferir DB; fallback env)
    to_stripe_price_id = to_plan_row.get("stripe_price_id") or PLAN_TO_PRICE.get(to_plan)
    if not to_stripe_price_id:
        raise HTTPException(status_code=500, detail="Plan destino sin stripe_price_id")

    if quota_total <= 0:
        raise HTTPException(status_code=500, detail="Entitlement quota_total inválido")

    # 4) Crédito proporcional (p99_price / 100) * remaining
    value_per_query = float(from_price_mxn) / float(quota_total)
    credit_mxn = int(max(0, int(remaining * value_per_query)))  # floor

    credit_mxn = min(credit_mxn, int(to_price_mxn))

    # Si cubre todo, checkout no puede 0 -> bloqueamos
    if credit_mxn >= int(to_price_mxn):
        raise HTTPException(
            status_code=400,
            detail="Tu crédito cubre el total; contacto soporte para migración manual",
        )

    # 5) Customer real
    email = _get_user_email(user_id)
    stripe_customer_id = _get_or_create_stripe_customer(user_id=user_id, email=email)

    # 6) Crear cupón 1 uso si hay crédito
    coupon_id = None
    if credit_mxn > 0:
        coupon_id = _create_one_time_coupon(
            amount_off_mxn=credit_mxn,
            user_id=user_id,
            from_entitlement_id=from_entitlement_id,
        )

    success_url = f"{FRONTEND_BASE_URL}/?billing=ok"
    cancel_url = f"{FRONTEND_BASE_URL}/?billing=cancel"

    # 7) Checkout Session para p199 + descuento
    try:
        session = stripe.checkout.Session.create(
            mode="payment",
            customer=stripe_customer_id,
            line_items=[{"price": to_stripe_price_id, "quantity": 1}],
            discounts=([{"coupon": coupon_id}] if coupon_id else None),
            success_url=success_url,
            cancel_url=cancel_url,
            client_reference_id=user_id,
            metadata={
                "app": "leyenmano",
                "billing_type": "upgrade",
                "user_id": user_id,
                "from_plan_code": from_plan,
                "to_plan_code": to_plan,
                "from_entitlement_id": from_entitlement_id,
                "credit_mxn": str(credit_mxn),
                "from_remaining": str(remaining),
                "from_quota_total": str(quota_total),
                "coupon_id": str(coupon_id) if coupon_id else "",
            },
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Stripe error: {type(e).__name__}: {str(e)[:220]}")

    return {
        "url": session.url,
        "credit_mxn": credit_mxn,
        "to_plan_price_mxn": int(to_price_mxn),
        "pay_estimated_mxn": int(to_price_mxn) - int(credit_mxn),
        "coupon_id": coupon_id,
    }