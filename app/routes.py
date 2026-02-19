from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, field_validator
from google import genai
from google.genai import types
from .cache import get_cache, MODEL_FLASH, MODEL_LITE
from .ratelimit import limiter
from .blocklist import check_ip_visitor
from .ip_utils import get_client_ip
from .usage_repo import upsert_visitor, insert_usage_event, ensure_user
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
    common_rules = """
POLICY (OBLIGATORIA):
- Responde en JSON PURO (sin ``` ni texto fuera del JSON).
- Cita ley y artículo en cada fundamento.
- Evita afirmar ilegalidad categórica si depende de prueba: usa "acto impugnable" / "podría constituir".
"""

    if policy.profile == "guest":
        return common_rules + """
MODO: GUEST
- response_mode = blindaje_only
- cards_per_step = 1
JSON SCHEMA ESTRICTO:
{
  "diagnostico": null,
  "fundamento_tactico": [
    {"ley": "string", "articulo": "string", "sustento": "string"}
  ],
  "ruta_blindaje": [
    {
      "paso": 1,
      "titulo": "string",
      "cards": [
        {
          "titulo": "string",
          "accion": "string",
          "que_decir": "string"
        }
      ]
    }
  ]
}
REGLAS:
- diagnostico SIEMPRE null.
- En cada paso, cards máximo 1.
- ruta_blindaje debe tener pasos numerados desde 1.
"""

    if policy.profile == "free":
        return common_rules + """
MODO: FREE (registrado sin plan)
- response_mode = diagnostico_y_blindaje
- cards_per_step = 2
JSON SCHEMA ESTRICTO:
{
  "diagnostico": {
    "resumen": "string",
    "gravedad": "Alta|Media|Baja"
  },
  "fundamento_tactico": [
    {"ley": "string", "articulo": "string", "sustento": "string"}
  ],
  "ruta_blindaje": [
    {
      "paso": 1,
      "titulo": "string",
      "cards": [
        {
          "titulo": "string",
          "accion": "string",
          "que_decir": "string"
        }
      ]
    }
  ]
}
REGLAS:
- diagnostico NO puede ser null.
- En cada paso, cards máximo 2.
"""

    # premium
    return common_rules + """
MODO: PREMIUM (plan activo)
- response_mode = full
- cards_per_step = full
JSON SCHEMA ESTRICTO:
{
  "diagnostico": {
    "resumen": "string",
    "gravedad": "Alta|Media|Baja"
  },
  "fundamento_tactico": [
    {"ley": "string", "articulo": "string", "sustento": "string"}
  ],
  "ruta_blindaje": [
    {
      "paso": 1,
      "titulo": "string",
      "cards": [
        {
          "titulo": "string",
          "accion": "string",
          "que_decir": "string",
          "que_no_decir": "string",
          "riesgo_si_no_haces": "string"
        }
      ]
    }
  ],
  "formatos_sugeridos": [
    {"tipo": "PROFECO|CONDUSEF|TRÁNSITO|COMAR|OTRO", "titulo": "string", "campos": ["string"]}
  ],
  "contactos": [
    {"institucion": "string", "contacto": "string"}
  ]
}
REGLAS:
- Sin recorte de cards.
- Si aplica, incluye formatos_sugeridos y contactos.
"""


@router.post("/policy")
@limiter.limit("30/minute")
def policy(request: Request, data: PolicyRequest):
    _validate_visitor_id(data.visitor_id)

    if data.user_id:
        ensure_user(data.user_id)

    upsert_visitor(data.visitor_id, data.user_id)
    pol = build_policy(data.visitor_id, data.user_id)

    return {
        "visitor_id": data.visitor_id,
        "user_id": data.user_id,
        "profile": pol.profile,
        "plan_code": pol.plan_code,
        "limits": {"daily": pol.daily_limit, "monthly": pol.monthly_limit},
        "remaining": pol.remaining,
        "reset_at": pol.reset_at_iso,
        "model": "flash" if pol.model_kind == "flash" else "flash-lite",
        "response": {"mode": pol.response_mode, "cards_per_step": pol.cards_per_step},
    }


@router.post("/consultar")
@limiter.limit("5/minute")
def consultar(request: Request, data: Consulta):
    ip = get_client_ip(request)
    _validate_visitor_id(data.visitor_id)

    if data.user_id:
        ensure_user(data.user_id)

    # anti-spam corto (minutos) por IP+visitor (NO cuotas)
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
                "remaining": 0,
            },
        )

    # Selección cache/modelo
    cache_kind = "flash" if pol.model_kind == "flash" else "lite"
    cache = get_cache(cache_kind)
    model_name = MODEL_FLASH if pol.model_kind == "flash" else MODEL_LITE

    overlay = _policy_overlay_text(pol)

        def _call_gemini(user_contents):
        return client.models.generate_content(
            model=model_name,
            contents=user_contents,
            config=types.GenerateContentConfig(cached_content=cache.name),
        )

    # IMPORTANTE:
    # Con cached_content, evitamos pasar system_instruction en el request.
    # Mandamos el POLICY como primer mensaje user.
# 1) intento normal
    try:
        response = _call_gemini(
            [
                types.Content(role="user", parts=[types.Part(text=overlay)]),
                types.Content(role="user", parts=[types.Part(text=data.pregunta.strip())]),
            ]
        )
    except Exception as e:
        insert_usage_event(
            visitor_id=data.visitor_id,
            user_id=data.user_id,
            profile=pol.profile,
            plan_code=pol.plan_code,
            model_used="flash" if pol.model_kind == "flash" else "flash-lite",
            endpoint="/consultar",
            allowed=False,
            reason=f"gemini_error:{type(e).__name__}:{str(e)[:180]}",
        )
        raise HTTPException(status_code=502, detail="IA no disponible. Reintenta.")

    text = (response.text or "").strip()

    def _is_pure_json(s: str) -> bool:
        return s.startswith("{") and s.endswith("}")

    # 2) retry de reformateo si viene con ``` o texto extra
    if not _is_pure_json(text):
        reformat_overlay = (
            "EMERGENCIA FORMATO:\n"
            "Debes responder ÚNICAMENTE con un objeto JSON puro.\n"
            "PROHIBIDO usar ``` o ```json.\n"
            "No escribas ninguna explicación.\n"
            "Toma el contenido de la respuesta previa y devuélvelo SOLO como JSON.\n"
        )

        try:
            response2 = _call_gemini(
                [
                    types.Content(role="user", parts=[types.Part(text=overlay)]),
                    types.Content(role="user", parts=[types.Part(text=reformat_overlay)]),
                    types.Content(role="user", parts=[types.Part(text=text)]),
                ]
            )
            text2 = (response2.text or "").strip()
            text = text2
        except Exception as e:
            insert_usage_event(
                visitor_id=data.visitor_id,
                user_id=data.user_id,
                profile=pol.profile,
                plan_code=pol.plan_code,
                model_used="flash" if pol.model_kind == "flash" else "flash-lite",
                endpoint="/consultar",
                allowed=False,
                reason=f"gemini_reformat_error:{type(e).__name__}:{str(e)[:180]}",
            )
            raise HTTPException(status_code=502, detail="Respuesta legal inválida. Reintenta.")

    # Guardrail JSON ESTRICTO (después del retry)
    if not _is_pure_json(text):
        bad_snip = text[:240].replace("\n", "\\n")
        insert_usage_event(
            visitor_id=data.visitor_id,
            user_id=data.user_id,
            profile=pol.profile,
            plan_code=pol.plan_code,
            model_used="flash" if pol.model_kind == "flash" else "flash-lite",
            endpoint="/consultar",
            allowed=False,
            reason=f"invalid_json_envelope:{bad_snip}",
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
        "respuesta": text,
    }