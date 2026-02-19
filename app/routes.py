from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, field_validator
from google import genai
from google.genai import types
from .cache import get_cache, MODEL_FLASH, MODEL_LITE
from .ratelimit import limiter
from .blocklist import check_ip_visitor
from .ip_utils import get_client_ip
from .usage_repo import upsert_visitor, insert_usage_event
from .policy_service import build_policy
import os

router = APIRouter()
client = genai.Client(api_key=os.environ["GOOGLE_API_KEY"])


class PolicyRequest(BaseModel):
    visitor_id: str
    user_id: str | None = None

    @field_validator("visitor_id")
    @classmethod
    def visitor_id_to_str(cls, v):
        return str(v).strip()

    @field_validator("user_id")
    @classmethod
    def user_id_to_str(cls, v):
        if v is None:
            return None
        s = str(v).strip()
        return s or None


class Consulta(BaseModel):
    pregunta: str
    visitor_id: str
    user_id: str | None = None
    locale: str | None = None
    source: str | None = None

    @field_validator("visitor_id")
    @classmethod
    def visitor_id_to_str(cls, v):
        return str(v).strip()

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


def _policy_overlay_text(policy):
    # Mensaje corto (no cacheado) para controlar salida/cantidad de cards
    # OJO: tu system_instruction debe exigir JSON estricto siempre.
    return (
        "POLICY:\n"
        f"- profile: {policy.profile}\n"
        f"- response_mode: {policy.response_mode}\n"
        f"- cards_per_step: {policy.cards_per_step}\n"
        "OUTPUT:\n"
        "Responde SIEMPRE en JSON estricto.\n"
        "Estructura mínima:\n"
        "{\n"
        '  "diagnostico": {...} | null,\n'
        '  "ruta_blindaje": [ { "paso": 1, "titulo": "...", "cards": [ ... ] } ]\n'
        "}\n"
        "Reglas:\n"
        "- Si response_mode=blindaje_only => diagnostico=null.\n"
        "- Si cards_per_step=1 => máximo 1 card por paso.\n"
        "- Si cards_per_step=2 => máximo 2 cards por paso.\n"
        "- Si cards_per_step=full => sin recorte.\n"
    )


@router.post("/policy")
@limiter.limit("30/minute")
def policy(request: Request, data: PolicyRequest):
    ip = get_client_ip(request)
    _validate_visitor_id(data.visitor_id)

    # anti-spam corto (minutos) por IP+visitor
    allowed, wait = check_ip_visitor(ip, data.visitor_id)
    if not allowed:
        raise HTTPException(status_code=429, detail=f"Bloqueado temporalmente. Intenta de nuevo en {wait}s.")

    # upsert visitor
    upsert_visitor(data.visitor_id, data.user_id)

    pol = build_policy(data.visitor_id, data.user_id)

    return {
        "visitor_id": data.visitor_id,
        "user_id": data.user_id,
        "profile": pol.profile,
        "plan_code": pol.plan_code,
        "limits": {
            "daily": pol.daily_limit,
            "monthly": pol.monthly_limit,
        },
        "remaining": pol.remaining,
        "reset_at": pol.reset_at_iso,
        "model": "flash" if pol.model_kind == "flash" else "flash-lite",
        "response": {
            "mode": pol.response_mode,
            "cards_per_step": pol.cards_per_step
        }
    }


@router.post("/consultar")
@limiter.limit("5/minute")
def consultar(request: Request, data: Consulta):
    ip = get_client_ip(request)
    _validate_visitor_id(data.visitor_id)

    # anti-spam corto (minutos)
    allowed, wait = check_ip_visitor(ip, data.visitor_id)
    if not allowed:
        insert_usage_event(
            visitor_id=data.visitor_id,
            user_id=data.user_id,
            profile="unknown",
            plan_code=None,
            model_used="n/a",
            endpoint="/consultar",
            allowed=False,
            reason=f"blocked_short:{wait}s",
        )
        raise HTTPException(status_code=429, detail=f"Bloqueado temporalmente. Intenta de nuevo en {wait}s.")

    if not data.pregunta or len(data.pregunta.strip()) < 3:
        raise HTTPException(status_code=400, detail="pregunta inválida")

    # upsert visitor
    upsert_visitor(data.visitor_id, data.user_id)

    # policy + cuotas negocio (DB)
    pol = build_policy(data.visitor_id, data.user_id)
    if pol.remaining <= 0:
        insert_usage_event(
            visitor_id=data.visitor_id,
            user_id=data.user_id,
            profile=pol.profile,
            plan_code=pol.plan_code,
            model_used="flash" if pol.model_kind == "flash" else "flash-lite",
            endpoint="/consultar",
            allowed=False,
            reason="quota_exceeded",
        )
        raise HTTPException(
            status_code=429,
            detail={
                "error": "QUOTA_EXCEEDED",
                "profile": pol.profile,
                "reset_at": pol.reset_at_iso,
                "remaining": 0
            }
        )

    # Selección cache/modelo
    cache_kind = "flash" if pol.model_kind == "flash" else "lite"
    cache = get_cache(cache_kind)
    model_name = MODEL_FLASH if pol.model_kind == "flash" else MODEL_LITE

    overlay = _policy_overlay_text(pol)
    contents = [
        types.Content(role="user", parts=[types.Part(text=overlay)]),
        types.Content(role="user", parts=[types.Part(text=data.pregunta.strip())]),
    ]

    response = client.models.generate_content(
        model=model_name,
        contents=contents,
        config=types.GenerateContentConfig(
            cached_content=cache.name
        )
    )

    text = (response.text or "").strip()

    # Guardrail JSON (igual que antes)
    if not text.startswith("{") or not text.endswith("}"):
        if not text.startswith("```json") or not text.endswith("```"):
            insert_usage_event(
                visitor_id=data.visitor_id,
                user_id=data.user_id,
                profile=pol.profile,
                plan_code=pol.plan_code,
                model_used="flash" if pol.model_kind == "flash" else "flash-lite",
                endpoint="/consultar",
                allowed=False,
                reason="invalid_model_output",
            )
            raise HTTPException(status_code=502, detail="Respuesta legal inválida. Reintenta.")

    # Registrar uso OK (consumo 1 consulta)
    insert_usage_event(
        visitor_id=data.visitor_id,
        user_id=data.user_id,
        profile=pol.profile,
        plan_code=pol.plan_code,
        model_used="flash" if pol.model_kind == "flash" else "flash-lite",
        endpoint="/consultar",
        allowed=True,
        reason=None,
    )

    return {
        "visitor_id": data.visitor_id,
        "user_id": data.user_id,
        "profile": pol.profile,
        "plan_code": pol.plan_code,
        "remaining_after": max(0, pol.remaining - 1),
        "reset_at": pol.reset_at_iso,
        "respuesta": text
    }