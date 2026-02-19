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
import json

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
    common = """
POLICY (OBLIGATORIA):
- Responde en JSON PURO (sin ``` ni texto fuera del JSON).
- NO inventes secciones fuera del schema.
- Si una clave es null en el schema, debe ser null (no arreglo, no lista, no texto).
"""

    if policy.profile == "guest":
        return common + """
PERFIL: GUEST
LIMITES:
- cards_per_step = 1
JSON SCHEMA ESTRICTO:
{
  "diagnostico": null,
  "fundamento_tactico": null,
  "ruta_blindaje": [
    {
      "paso": 1,
      "titulo": "string",
      "cards": [
        { "titulo": "string", "accion": "string", "que_decir": "string" }
      ]
    }
  ],
  "formato_emergencia": null,
  "telefono_contacto": null
}
REGLAS:
- diagnostico MUST be null
- fundamento_tactico MUST be null
- formato_emergencia MUST be null
- telefono_contacto MUST be null
- Máximo 1 card por paso.
"""

    if policy.profile == "free":
        return common + """
PERFIL: FREE (registrado sin plan)
LIMITES:
- cards_per_step = 1
JSON SCHEMA ESTRICTO:
{
  "diagnostico": {
    "resumen": "string",
    "gravedad": "Alta|Media|Baja"
  },
  "fundamento_tactico": null,
  "ruta_blindaje": [
    {
      "paso": 1,
      "titulo": "string",
      "cards": [
        { "titulo": "string", "accion": "string", "que_decir": "string" }
      ]
    }
  ],
  "formato_emergencia": null,
  "telefono_contacto": null
}
REGLAS:
- diagnostico NO puede ser null
- fundamento_tactico MUST be null
- formato_emergencia MUST be null
- telefono_contacto MUST be null
- Máximo 1 card por paso.
"""

    # premium
    return common + """
PERFIL: PREMIUM (plan activo)
JSON SCHEMA ESTRICTO:
{
  "diagnostico": {
    "resumen": "string",
    "gravedad": "Alta|Media|Baja"
  },
  "fundamento_tactico": [
    {"ley":"string","articulo":"string","sustento":"string"}
  ],
  "ruta_blindaje": [
    {
      "paso": 1,
      "titulo": "string",
      "cards": [
        {
          "titulo":"string",
          "accion":"string",
          "que_decir":"string",
          "que_no_decir":"string",
          "riesgo_si_no_haces":"string"
        }
      ]
    }
  ],
  "formato_emergencia": null,
  "telefono_contacto": null
}
REGLAS:
- ruta_blindaje debe tener 3+ pasos cuando el caso lo amerite.
- Sin recorte de cards.
- Incluir fundamento_tactico (no null).
- formato_emergencia y telefono_contacto: si no aplica, null.
"""


def _limit_cards_to_one(o: dict):
    rb = o.get("ruta_blindaje")
    if isinstance(rb, list):
        for step in rb:
            if isinstance(step, dict) and isinstance(step.get("cards"), list):
                step["cards"] = step["cards"][:1]


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


def enforce_profile_shape(obj: dict, profile: str) -> dict:
    # asegurar llaves base
    for k in ["diagnostico", "fundamento_tactico", "ruta_blindaje", "formato_emergencia", "telefono_contacto"]:
        if k not in obj:
            obj[k] = None

    if profile == "guest":
        obj["diagnostico"] = None
        obj["fundamento_tactico"] = None
        obj["formato_emergencia"] = None
        obj["telefono_contacto"] = None
        _limit_cards_to_one(obj)

    elif profile == "free":
        obj["fundamento_tactico"] = None
        obj["formato_emergencia"] = None
        obj["telefono_contacto"] = None
        _limit_cards_to_one(obj)

    else:
        # premium: no recorte
        pass

    return obj


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
            detail={"error": "QUOTA_EXCEEDED", "profile": pol.profile, "reset_at": pol.reset_at_iso, "remaining": 0},
        )

    cache_kind = "flash" if pol.model_kind == "flash" else "lite"
    cache = get_cache(cache_kind)
    model_name = MODEL_FLASH if pol.model_kind == "flash" else MODEL_LITE

    overlay = _policy_overlay_text(pol)

    try:
        response = client.models.generate_content(
            model=model_name,
            contents=[
                types.Content(role="user", parts=[types.Part(text=overlay)]),
                types.Content(role="user", parts=[types.Part(text=data.pregunta.strip())]),
            ],
            config=types.GenerateContentConfig(cached_content=cache.name),
        )
        print(cache)
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

    raw = (response.text or "").strip()
    normalized = normalize_model_output_to_json(raw)

    if not normalized:
        bad_snip = raw[:240].replace("\n", "\\n")
        insert_usage_event(
            visitor_id=data.visitor_id,
            user_id=data.user_id,
            profile=pol.profile,
            plan_code=pol.plan_code,
            model_used="flash" if pol.model_kind == "flash" else "flash-lite",
            endpoint="/consultar",
            allowed=False,
            reason=f"invalid_model_output:{bad_snip}",
        )
        raise HTTPException(status_code=502, detail="Respuesta legal inválida. Reintenta.")

    try:
        obj = json.loads(normalized)
    except Exception:
        bad_snip = normalized[:240].replace("\n", "\\n")
        insert_usage_event(
            visitor_id=data.visitor_id,
            user_id=data.user_id,
            profile=pol.profile,
            plan_code=pol.plan_code,
            model_used="flash" if pol.model_kind == "flash" else "flash-lite",
            endpoint="/consultar",
            allowed=False,
            reason=f"json_parse_error:{bad_snip}",
        )
        raise HTTPException(status_code=502, detail="Respuesta legal inválida. Reintenta.")

    obj = enforce_profile_shape(obj, pol.profile)

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

    resp = {
        "visitor_id": data.visitor_id,
        "user_id": data.user_id,
        "profile": pol.profile,
        "plan_code": pol.plan_code,
        "remaining_after": max(0, pol.remaining - 1),
        "reset_at": pol.reset_at_iso,
        "respuesta": obj,
    }

    if os.getenv("ENV") != "production":
        resp["debug_raw"] = raw[:2000]

    return resp