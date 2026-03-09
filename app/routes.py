from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, field_validator
from google import genai
from google.genai import types
from .cache import get_cache, MODEL_FLASH, MODEL_LITE
from .ratelimit import limiter
from .blocklist import check_identity
from .ip_utils import get_client_ip, hash_ip
from .usage_repo import (
    upsert_visitor,
    insert_usage_event,
    ensure_user,
    consume_entitlement,
    refund_entitlement,
    get_latest_entitlement_any_status,
)
from .policy_service import build_policy
from .db import pool

import os
import json
import hashlib
from datetime import datetime, timezone


router = APIRouter()
client = genai.Client(api_key=os.environ["GOOGLE_API_KEY"])

# ======================================================
# 🍪 COOKIES / SESSION HELPERS
# ======================================================

ENV = os.getenv("ENV", "development")
COOKIE_DOMAIN = os.getenv("COOKIE_DOMAIN", ".leyenmano.com" if ENV == "production" else None)
SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "session_id")
VISITOR_COOKIE_NAME = os.getenv("VISITOR_COOKIE_NAME", "visitor_id")
SESSION_PEPPER = os.getenv("SESSION_PEPPER", "")  # recomendado setear en prod

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _session_hash(session_id: str) -> str:
    # hash con "pepper" opcional (recomendado para prod)
    base = f"{SESSION_PEPPER}:{session_id}" if SESSION_PEPPER else session_id
    return _sha256_hex(base)

def _get_cookie(request: Request, key: str) -> str | None:
    v = request.cookies.get(key)
    if not v:
        return None
    v = str(v).strip()
    return v or None

def _set_cookie_common(response: Response, key: str, value: str, *, max_age: int):
    # Nota: si COOKIE_DOMAIN es None (dev), no se setea domain
    kwargs = dict(
        key=key,
        value=value,
        httponly=True,      # visitor_id no es sensible
        secure=(ENV == "production"),
        samesite="lax",
        max_age=max_age,
        path="/",
    )
    if COOKIE_DOMAIN:
        kwargs["domain"] = COOKIE_DOMAIN
    response.set_cookie(**kwargs)

def _set_visitor_cookie(response: Response, visitor_id: str):
    # 180 días
    _set_cookie_common(response, VISITOR_COOKIE_NAME, visitor_id, max_age=60 * 60 * 24 * 180)

def _delete_cookie(response: Response, key: str):
    kwargs = dict(
        key=key,
        path="/",
    )
    if COOKIE_DOMAIN:
        kwargs["domain"] = COOKIE_DOMAIN
    response.delete_cookie(**kwargs)

def _get_session_user_id(request: Request) -> str | None:
    """
    Lee cookie session_id, busca en DB sessions(session_id_hash) si está vigente.
    Devuelve user_id (str) o None.
    """
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

            # opcional: actualizar last_seen_at
            if row:
                cur.execute(
                    "UPDATE sessions SET last_seen_at = NOW() WHERE session_id_hash = %s",
                    (sid_hash,),
                )
        conn.commit()

    if not row:
        return None

    return str(row[0])

def _iso(dt) -> str | None:
    if not dt:
        return None
    try:
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        # si ya viene como datetime con tz, isoformat igual funciona
        return dt.isoformat()

def _revoke_session(request: Request):
    sid = _get_cookie(request, SESSION_COOKIE_NAME)
    if not sid:
        return
    sid_hash = _session_hash(sid)
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE sessions
                SET revoked_at = NOW()
                WHERE session_id_hash = %s
                  AND revoked_at IS NULL
                """,
                (sid_hash,),
            )
        conn.commit()

# ======================================================
# MODELOS
# ======================================================

class PolicyRequest(BaseModel):
    visitor_id: str | None = None
    user_id: str | None = None

    @field_validator("visitor_id")
    @classmethod
    def visitor_id_to_str(cls, v):
        if v is None:
            return None
        return str(v).strip() or None

    @field_validator("user_id")
    @classmethod
    def user_id_to_str(cls, v):
        if v is None:
            return None
        s = str(v).strip()
        return s or None


class Consulta(BaseModel):
    pregunta: str
    visitor_id: str | None = None
    user_id: str | None = None
    locale: str | None = None
    source: str | None = None
    first_experience_demo: bool = False

    @field_validator("visitor_id")
    @classmethod
    def visitor_id_to_str(cls, v):
        if v is None:
            return None
        return str(v).strip() or None

    @field_validator("user_id")
    @classmethod
    def user_id_to_str(cls, v):
        if v is None:
            return None
        s = str(v).strip()
        return s or None


def _validate_visitor_id(visitor_id: str):
    if len(visitor_id) < 6 or len(visitor_id) > 80:
        raise HTTPException(status_code=400, detail="visitor_id inválido")

def _effective_visitor_id(request: Request, body_visitor_id: str | None) -> str | None:
    # prioridad: body -> cookie
    if body_visitor_id:
        return body_visitor_id
    return _get_cookie(request, VISITOR_COOKIE_NAME)

def _effective_user_id(request: Request, body_user_id: str | None) -> str | None:
    # 🔒 Nunca confiar en user_id del body
    return _get_session_user_id(request)

# ======================================================
# OVERLAY / NORMALIZACIÓN
# ======================================================

def _policy_overlay_text_for_profile(profile: str, tier: str | None = None):
    common = """
POLICY (OBLIGATORIA):
- Responde en JSON PURO (sin ``` ni texto fuera del JSON).
- Respeta EXACTAMENTE el schema del perfil.
- Si una clave es null en el schema, debe ser null (no lista, no texto).
- La Ruta de Blindaje debe incluir SIEMPRE 3 pasos mínimos:
  paso_1_inmediato, paso_2_discurso, paso_3_denuncia.
"""

    if profile == "guest":
        return common + """
PERFIL: GUEST
- cards_per_step = 1
SCHEMA ESTRICTO:
{
  "Diagnóstico Jurídico": null,
  "Fundamento Táctico": null,
  "Ruta de Blindaje": {
    "paso_1_inmediato": [
      {"titulo":"string","accion":"string"}
    ],
    "paso_2_discurso": {
      "que_no_decir": ["string"],
      "que_si_decir": ["string"]
    },
    "paso_3_denuncia": [
      {"titulo":"string","accion":"string"}
    ]
  },
  "Riesgos y Consecuencias": null,
  "Formato de Emergencia": null,
  "Teléfono de contacto": null
}
REGLAS:
- En paso_1_inmediato: máximo 1 card (1 objeto en la lista).
- En paso_2_discurso.que_no_decir: máximo 1 card (1 objeto en la lista).
- En paso_2_discurso.que_si_decir: máximo 1 card (1 objeto en la lista).
- En paso_3_denuncia: máximo 1 card (1 objeto en la lista).
- Mantén paso_2_discurso con listas cortas (2–5 frases).
"""

    if profile == "free":
        return common + """
PERFIL: FREE
- cards_per_step = 1
SCHEMA ESTRICTO:
{
  "Diagnóstico Jurídico": {
    "resumen":"string",
    "gravedad":"Alta|Media|Baja"
  },
  "Fundamento Táctico": null,
  "Ruta de Blindaje": {
    "paso_1_inmediato": [
      {"titulo":"string","accion":"string"}
    ],
    "paso_2_discurso": {
      "que_no_decir": ["string"],
      "que_si_decir": ["string"]
    },
    "paso_3_denuncia": [
      {"titulo":"string","accion":"string"}
    ]
  },
  "Riesgos y Consecuencias": null,
  "Formato de Emergencia": null,
  "Teléfono de contacto": null
}
REGLAS:
- Diagnóstico Jurídico NO puede ser null.
- En paso_1_inmediato: máximo 1 card (1 objeto en la lista).
- En paso_2_discurso.que_no_decir: máximo 1 card (1 objeto en la lista).
- En paso_2_discurso.que_si_decir: máximo 1 card (1 objeto en la lista).
- En paso_3_denuncia: máximo 1 card (1 objeto en la lista).
- Mantén paso_2_discurso con listas cortas (2–5 frases).
"""

    if profile == "premium" and tier == "premium_basic":
        return common + """
PERFIL: PREMIUM_BASIC
SCHEMA ESTRICTO:
{
  "Diagnóstico Jurídico": {
    "resumen":"string",
    "gravedad":"Alta|Media|Baja"
  },
  "Fundamento Táctico": [
    {"ley":"string","articulo":"string","sustento":"string"}
  ],
  "Ruta de Blindaje": {
    "paso_1_inmediato": [
      {"titulo":"string","accion":"string","que_decir":"string"}
    ],
    "paso_2_discurso": {
      "que_no_decir": ["string"],
      "que_si_decir": ["string"]
    },
    "paso_3_denuncia": [
      {"titulo":"string","accion":"string","que_decir":"string"}
    ],
    "paso_4_adicional": [
      {"titulo":"string","accion":"string","que_decir":"string"}
    ]
  },
  "Formato de Emergencia": {
    "disponible": true,
    "titulo": "string",
    "campos": ["string"]
  },
  "Teléfono de contacto": [
    {"Institucion":"string","contacto":"string","mision":"string"}
  ]
}
REGLAS:
- En Fundamento Táctico no juntes las leyes que aplican, explica cada una por separado.
- Debes incluir SIEMPRE paso_1_inmediato, paso_2_discurso, paso_3_denuncia.
- En paso_1_inmediato: puedes agregar mas acciones en la lista cuando sea necesario.
- En paso_3_denuncia: puedes agregar mas denuncias en la lista cuando sea necesario.
- Puedes agregar paso_4_adicional, paso_5_adicional, etc. cuando sea necesario.
- Si no aplica Riesgos y Consecuencias, Formato de Emergencia o Teléfono, usa null (no inventar).
- En campos de Formato de Emergencia, solo enlista los campos que son necesarios para llenar el formato
"""

    return common + """
PERFIL: PREMIUM
SCHEMA ESTRICTO:
{
  "Diagnóstico Jurídico": {
    "resumen":"string",
    "gravedad":"Alta|Media|Baja"
  },
  "Fundamento Táctico": [
    {"ley":"string","articulo":"string","sustento":"string"}
  ],
  "Ruta de Blindaje": {
    "paso_1_inmediato": [
      {"titulo":"string","accion":"string","que_decir":"string"}
    ],
    "paso_2_discurso": {
      "que_no_decir": ["string"],
      "que_si_decir": ["string"]
    },
    "paso_3_denuncia": [
      {"titulo":"string","accion":"string","que_decir":"string"}
    ],
    "paso_4_adicional": [
      {"titulo":"string","accion":"string","que_decir":"string"}
    ]
  },
  "Riesgos y Consecuencias": {
    "errores_comunes": ["string"],
    "frases_que_empeoran": ["string"],
    "no_entregar": ["string"],
    "no_firmar": ["string"],
    "momentos_criticos": ["string"]
  },
  "Formato de Emergencia": {
    "disponible": true,
    "titulo": "string",
    "campos": ["string"]
  },
  "Teléfono de contacto": [
    {"Institucion":"string","contacto":"string","mision":"string"}
  ]
}
REGLAS:
- En Fundamento Táctico no juntes las leyes que aplican, explica cada una por separado.
- Debes incluir SIEMPRE paso_1_inmediato, paso_2_discurso, paso_3_denuncia.
- En paso_1_inmediato: puedes agregar mas acciones en la lista cuando sea necesario.
- En paso_3_denuncia: puedes agregar mas denuncias en la lista cuando sea necesario.
- Puedes agregar paso_4_adicional, paso_5_adicional, etc. cuando sea necesario.
- Si no aplica Riesgos y Consecuencias, Formato de Emergencia o Teléfono, usa null (no inventar).
- En campos de Formato de Emergencia, solo enlista los campos que son necesarios para llenar el formato
"""

def _policy_overlay_text(policy):
    return _policy_overlay_text_for_profile(policy.profile, getattr(policy, "tier", None))

LEGACY_KEYS = {
    "diagnostico": "Diagnóstico Jurídico",
    "fundamento_tactico": "Fundamento Táctico",
    "ruta_blindaje": "Ruta de Blindaje",
    "riesgos_consecuencias": "Riesgos y Consecuencias",
    "formato_emergencia": "Formato de Emergencia",
    "telefono_contacto": "Teléfono de contacto",
}

LOWERCASE_KEYS = [
    "diagnostico",
    "fundamento_tactico",
    "ruta_blindaje",
    "riesgos_consecuencias",
    "formato_emergencia",
    "telefono_contacto",
]

def _drop_lowercase_keys_if_present(obj: dict) -> None:
    for k in LOWERCASE_KEYS:
        if k in obj:
            obj.pop(k, None)

def _limit_legacy_cards_guest_free(obj: dict) -> None:
    rb = obj.get("Ruta de Blindaje")
    if not isinstance(rb, dict):
        return

    p1 = rb.get("paso_1_inmediato")
    if isinstance(p1, list):
        rb["paso_1_inmediato"] = p1[:1]

    p3 = rb.get("paso_3_denuncia")
    if isinstance(p3, list):
        rb["paso_3_denuncia"] = p3[:1]

def _upgrade_lowercase_to_legacy(obj: dict) -> None:
    for low, legacy in LEGACY_KEYS.items():
        if legacy not in obj and low in obj:
            obj[legacy] = obj[low]

def enforce_profile_shape_legacy(obj: dict, profile: str) -> dict:
    _drop_lowercase_keys_if_present(obj)

    for k in [
        "Diagnóstico Jurídico",
        "Fundamento Táctico",
        "Ruta de Blindaje",
        "Riesgos y Consecuencias",
        "Formato de Emergencia",
        "Teléfono de contacto",
    ]:
        if k not in obj:
            obj[k] = None

    if profile == "guest":
        obj["Diagnóstico Jurídico"] = None
        obj["Fundamento Táctico"] = None
        obj["Riesgos y Consecuencias"] = None
        obj["Formato de Emergencia"] = None
        obj["Teléfono de contacto"] = None
        _limit_legacy_cards_guest_free(obj)

    elif profile == "free":
        obj["Fundamento Táctico"] = None
        obj["Riesgos y Consecuencias"] = None
        obj["Formato de Emergencia"] = None
        obj["Teléfono de contacto"] = None
        _limit_legacy_cards_guest_free(obj)

    else:
        pass

    return obj

def _strip_code_fences(s: str) -> str:
    t = (s or "").strip()
    if t.startswith("```"):
        first_nl = t.find("\n")
        if first_nl != -1:
            t = t[first_nl + 1 :]
        if t.rstrip().endswith("```"):
            t = t.rstrip()[:-3]
    return t.strip()

def _extract_first_json_object(s: str) -> str | None:
    start = s.find("{")
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(s)):
        ch = s[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return s[start : i + 1].strip()
    return None

def normalize_model_output_to_json(text: str) -> str | None:
    t = (text or "").strip()
    t = _strip_code_fences(t)
    if t.startswith("{") and t.endswith("}"):
        return t
    return _extract_first_json_object(t)

def _get_user_email(user_id: str) -> str | None:
    """
    Lee el email del usuario desde DB. Ajusta el nombre de tabla/columna si difiere.
    Esperado: users(email).
    """
    if not user_id:
        return None

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT email
                FROM users
                WHERE user_id = %s
                """,
                (user_id,),
            )
            row = cur.fetchone()

    if not row:
        return None

    email = row[0]
    return str(email) if email else None

# ======================================================
# ✅ NUEVOS ENDPOINTS: /me y /logout
# ======================================================

@router.get("/me")
def me(request: Request):
    visitor_id = _effective_visitor_id(request, None)
    user_id = _effective_user_id(request, None)

    # Si no hay visitor_id aún, solo regresa estado vacío (frontend puede crear uno)
    if not visitor_id:
        email = _get_user_email(user_id) if user_id else None
        latest_ent = get_latest_entitlement_any_status(user_id) if user_id else None
        billing_status = None
        if latest_ent:
            billing_status = {
                "status": latest_ent.get("status"),
                "plan_code": latest_ent.get("plan_code"),
                "quota_total": latest_ent.get("quota_total"),
                "remaining": latest_ent.get("remaining"),
                "valid_until": _iso(latest_ent.get("valid_until")),
                "created_at": _iso(latest_ent.get("created_at")),
            }
        return {
            "visitor_id": None,
            "user_id": user_id,
            "email": email,  # ✅
            "profile": "guest" if not user_id else "free",
            "tier": "guest" if not user_id else "free",  # ✅ NUEVO
            "plan_code": None,
            "remaining": None,
            "reset_at": None,
            "subscription_status": None,
            "subscription_start": None,
            "subscription_end": None,
            "billing_status": billing_status,
        }

    _validate_visitor_id(visitor_id)

    if user_id:
        ensure_user(user_id)

    upsert_visitor(visitor_id, user_id)
    ip = get_client_ip(request)
    ip_hash = hash_ip(ip)
    pol = build_policy(visitor_id, user_id, ip_hash)
    email = _get_user_email(user_id) if user_id else None

    return {
        "visitor_id": visitor_id,
        "user_id": user_id,
        "email": email,  # ✅
        "profile": pol.profile,
        "tier": pol.tier,
        "plan_code": pol.plan_code,
        "limits": {"daily": pol.daily_limit, "monthly": pol.monthly_limit},
        "remaining": pol.remaining,
        "reset_at": pol.reset_at_iso,
        "model": "flash" if pol.model_kind == "flash" else "flash-lite",
        "response": {"mode": pol.response_mode, "cards_per_step": pol.cards_per_step},
        "subscription_status": pol.subscription_status,
        "subscription_start": pol.subscription_start_iso,
        "subscription_end": pol.subscription_end_iso,
    }

@router.post("/logout")
def logout(request: Request, response: Response):
    # revoca sesión en DB y borra cookie
    _revoke_session(request)
    _delete_cookie(response, SESSION_COOKIE_NAME)
    return {"ok": True}

# ======================================================
# API PRINCIPAL
# ======================================================

@router.post("/policy")
@limiter.limit("30/minute")
def policy(request: Request, response: Response, data: PolicyRequest):
    visitor_id = _effective_visitor_id(request, data.visitor_id)
    if not visitor_id:
        raise HTTPException(status_code=400, detail="visitor_id requerido (body o cookie)")

    _validate_visitor_id(visitor_id)
    _set_visitor_cookie(response, visitor_id)

    user_id = _effective_user_id(request, data.user_id)
    email = None

    if user_id:
        ensure_user(user_id)
        email = _get_user_email(user_id)

    upsert_visitor(visitor_id, user_id)

    ip = get_client_ip(request)
    ip_hash = hash_ip(ip)

    # ------------------------------------------------------
    # ✅ Blocklist "suave" también para /policy (tu config ENDPOINT_LIMITS["/policy"])
    # ------------------------------------------------------
    allowed, wait, breason = check_identity(ip=ip, visitor_id=visitor_id, endpoint="/policy")
    if not allowed:
        insert_usage_event(
            visitor_id=visitor_id,
            user_id=user_id,
            profile="unknown",
            plan_code=None,
            model_used="n/a",
            endpoint="/policy",
            allowed=False,
            reason=f"{breason}:{wait}s",
            ip_hash=ip_hash,
            entitlement_id=None,
        )
        raise HTTPException(
            status_code=429,
            detail={
                "error": "RATE_LIMITED",
                "reason": breason,
                "wait_seconds": int(wait),
            },
        )

    # ------------------------------------------------------
    # Policy normal
    # ------------------------------------------------------
    pol = build_policy(visitor_id, user_id, ip_hash)

    latest_ent = get_latest_entitlement_any_status(user_id) if user_id else None

    billing_status = None
    if latest_ent:
        billing_status = {
            "status": latest_ent.get("status"),
            "plan_code": latest_ent.get("plan_code"),
            "quota_total": latest_ent.get("quota_total"),
            "remaining": latest_ent.get("remaining"),
            "valid_until": _iso(latest_ent.get("valid_until")),
            "created_at": _iso(latest_ent.get("created_at")),
        }

    return {
        "visitor_id": visitor_id,
        "user_id": user_id,
        "email": email,
        "profile": pol.profile,
        "tier": pol.tier,
        "plan_code": pol.plan_code,
        "limits": {"daily": pol.daily_limit, "monthly": pol.monthly_limit},
        "remaining": pol.remaining,
        "reset_at": pol.reset_at_iso,
        "model": "flash" if pol.model_kind == "flash" else "flash-lite",
        "response": {"mode": pol.response_mode, "cards_per_step": pol.cards_per_step},
        "subscription_status": pol.subscription_status,
        "subscription_start": pol.subscription_start_iso,
        "subscription_end": pol.subscription_end_iso,
        "billing_status": billing_status,
    }

@router.post("/consultar")
@limiter.limit("5/minute")
def consultar(request: Request, response: Response, data: Consulta):
    ip = get_client_ip(request)
    ip_hash = hash_ip(ip)

    visitor_id = _effective_visitor_id(request, data.visitor_id)
    if not visitor_id:
        raise HTTPException(status_code=400, detail="visitor_id requerido (body o cookie)")

    _validate_visitor_id(visitor_id)
    _set_visitor_cookie(response, visitor_id)

    user_id = _effective_user_id(request, data.user_id)
    if user_id:
        ensure_user(user_id)


    allowed, wait, breason = check_identity(ip=ip, visitor_id=visitor_id, endpoint="/consultar")
    if not allowed:
        insert_usage_event(
            visitor_id=visitor_id,
            user_id=user_id,
            profile="unknown",
            plan_code=None,
            model_used="n/a",
            endpoint="/consultar",
            allowed=False,
            reason=f"{breason}:{wait}s",
            ip_hash=ip_hash,
            entitlement_id=None,
        )
        raise HTTPException(
            status_code=429,
            detail={
                "error": "RATE_LIMITED",
                "reason": breason,
                "wait_seconds": wait,
            },
        )

    if not data.pregunta or len(data.pregunta.strip()) < 3:
        raise HTTPException(status_code=400, detail="pregunta inválida")

    upsert_visitor(visitor_id, user_id)

    pol = build_policy(visitor_id, user_id, ip_hash)

    is_first_experience_demo = (
        data.first_experience_demo is True
        and not user_id
        and pol.profile == "guest"
    )

    overlay_profile = "free" if is_first_experience_demo else pol.profile
    overlay_tier = pol.tier

    # ------------------------------------------------------
    # PREMIUM: consumir entitlement (atómico)
    # ------------------------------------------------------
    consumed = None
    if pol.profile == "premium" and user_id:
        consumed = consume_entitlement(user_id)
        if not consumed:
            insert_usage_event(
                visitor_id=visitor_id,
                user_id=user_id,
                profile=pol.profile,
                plan_code=pol.plan_code,
                model_used="flash" if pol.model_kind == "flash" else "flash-lite",
                endpoint="/consultar",
                allowed=False,
                reason="quota_exceeded",
                ip_hash=ip_hash,
                entitlement_id=None,
            )
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "QUOTA_EXCEEDED",
                    "profile": pol.profile,
                    "reset_at": pol.reset_at_iso,
                    "remaining": 0,
                    "subscription_status": pol.subscription_status,
                    "subscription_start": pol.subscription_start_iso,
                    "subscription_end": pol.subscription_end_iso,
                },
            )

    # ------------------------------------------------------
    # FREE/GUEST: se conserva la lógica actual basada en pol.remaining
    # ------------------------------------------------------
    if pol.profile != "premium" and pol.remaining <= 0:
        insert_usage_event(
            visitor_id=visitor_id,
            user_id=user_id,
            profile=pol.profile,
            plan_code=pol.plan_code,
            model_used="flash" if pol.model_kind == "flash" else "flash-lite",
            endpoint="/consultar",
            allowed=False,
            reason="quota_exceeded",
            ip_hash=ip_hash,
            entitlement_id=None,
        )
        raise HTTPException(
            status_code=429,
            detail={
                "error": "QUOTA_EXCEEDED",
                "profile": pol.profile,
                "reset_at": pol.reset_at_iso,
                "remaining": 0,
                "subscription_status": pol.subscription_status,
                "subscription_start": pol.subscription_start_iso,
                "subscription_end": pol.subscription_end_iso,
            },
        )

    cache_kind = "flash" if pol.model_kind == "flash" else "lite"
    cache = get_cache(cache_kind)
    model_name = MODEL_FLASH if pol.model_kind == "flash" else MODEL_LITE

    overlay = _policy_overlay_text_for_profile(overlay_profile, overlay_tier)

    try:
        response_ai = client.models.generate_content(
            model=model_name,
            contents=[
                types.Content(role="user", parts=[types.Part(text=overlay)]),
                types.Content(role="user", parts=[types.Part(text=data.pregunta.strip())]),
            ],
            config=types.GenerateContentConfig(
                cached_content=cache.name
            ),
        )
    except Exception as e:
        if consumed and consumed.get("entitlement_id"):
            refund_entitlement(consumed["entitlement_id"])
        insert_usage_event(
            visitor_id=visitor_id,
            user_id=user_id,
            profile=pol.profile,
            plan_code=pol.plan_code,
            model_used="flash" if pol.model_kind == "flash" else "flash-lite",
            endpoint="/consultar",
            allowed=False,
            reason=f"gemini_error:{type(e).__name__}:{str(e)[:180]}",
            ip_hash=ip_hash,
            entitlement_id=(consumed["entitlement_id"] if consumed else None),
        )
        raise HTTPException(status_code=502, detail="IA no disponible. Reintenta.")

    raw = (response_ai.text or "").strip()
    normalized = normalize_model_output_to_json(raw)

    if not normalized:
        bad_snip = raw[:240].replace("\n", "\\n")
        if consumed and consumed.get("entitlement_id"):
            refund_entitlement(consumed["entitlement_id"])
        insert_usage_event(
            visitor_id=visitor_id,
            user_id=user_id,
            profile=pol.profile,
            plan_code=pol.plan_code,
            model_used="flash" if pol.model_kind == "flash" else "flash-lite",
            endpoint="/consultar",
            allowed=False,
            reason=f"invalid_model_output:{bad_snip}",
            ip_hash=ip_hash,
            entitlement_id=(consumed["entitlement_id"] if consumed else None),
        )
        raise HTTPException(status_code=502, detail="Respuesta legal inválida. Reintenta.")

    try:
        obj = json.loads(normalized)
    except Exception:
        bad_snip = normalized[:240].replace("\n", "\\n")
        if consumed and consumed.get("entitlement_id"):
            refund_entitlement(consumed["entitlement_id"])
        insert_usage_event(
            visitor_id=visitor_id,
            user_id=user_id,
            profile=pol.profile,
            plan_code=pol.plan_code,
            model_used="flash" if pol.model_kind == "flash" else "flash-lite",
            endpoint="/consultar",
            allowed=False,
            reason=f"json_parse_error:{bad_snip}",
            ip_hash=ip_hash,
            entitlement_id=(consumed["entitlement_id"] if consumed else None),
        )
        raise HTTPException(status_code=502, detail="Respuesta legal inválida. Reintenta.")

    _upgrade_lowercase_to_legacy(obj)
    _drop_lowercase_keys_if_present(obj)
    shape_profile = "free" if is_first_experience_demo else pol.profile
    obj = enforce_profile_shape_legacy(obj, shape_profile)
    remaining_after = consumed["remaining_after"] if consumed else max(0, pol.remaining - 1)

    insert_usage_event(
        visitor_id=visitor_id,
        user_id=user_id,
        profile=pol.profile,
        plan_code=pol.plan_code,
        model_used="flash" if pol.model_kind == "flash" else "flash-lite",
        endpoint="/consultar",
        allowed=True,
        reason=None,
        ip_hash=ip_hash,
        entitlement_id=(consumed["entitlement_id"] if consumed else None),
    )

    resp = {
        "visitor_id": visitor_id,
        "user_id": user_id,
        "profile": pol.profile,
        "tier": pol.tier,  # ✅ NUEVO
        "plan_code": pol.plan_code,
        "remaining_after": remaining_after,
        "reset_at": pol.reset_at_iso,
        "respuesta": obj,
        "subscription_status": pol.subscription_status,
        "subscription_start": pol.subscription_start_iso,
        "subscription_end": pol.subscription_end_iso,
        "first_experience_demo_applied": is_first_experience_demo,
        "response_profile": shape_profile,
    }

    if os.getenv("ENV") != "production":
        resp["debug_raw"] = raw[:2000]

    return resp