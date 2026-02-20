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
- Respeta EXACTAMENTE el schema del perfil.
- Si una clave es null en el schema, debe ser null (no lista, no texto).
- La Ruta de Blindaje debe incluir SIEMPRE 3 pasos mínimos:
  paso_1_inmediato, paso_2_discurso, paso_3_denuncia.
"""

    if policy.profile == "guest":
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

    if policy.profile == "free":
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

    # premium
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

LEGACY_KEYS = {
    "diagnostico": "Diagnóstico Jurídico",
    "fundamento_tactico": "Fundamento Táctico",
    "ruta_blindaje": "Ruta de Blindaje",
    "riesgos_consecuencias": "Riesgos y Consecuencias",
    "formato_emergencia": "Formato de Emergencia",
    "telefono_contacto": "Teléfono de contacto",
}

LEGACY_TOP_KEYS = [
    "Diagnóstico Jurídico",
    "Fundamento Táctico",
    "Ruta de Blindaje",
    "Riesgos y Consecuencias",
    "Formato de Emergencia",
    "Teléfono de contacto",
]

LOWERCASE_KEYS = [
    "diagnostico",
    "fundamento_tactico",
    "ruta_blindaje",
    "riesgos_consecuencias",
    "formato_emergencia",
    "telefono_contacto",
]

def _drop_lowercase_keys_if_present(obj: dict) -> None:
    # Si el modelo metió llaves nuevas (minúsculas/snake_case), las quitamos
    for k in LOWERCASE_KEYS:
        if k in obj:
            obj.pop(k, None)

def _limit_legacy_cards_guest_free(obj: dict) -> None:
    """
    guest/free: 1 card en paso_1_inmediato y 1 card en paso_3_denuncia
    paso_2_discurso: listas cortas (no recortamos aquí, solo respetamos lo que venga)
    """
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
    # Si viene snake_case y NO viene legacy, la subimos a legacy.
    for low, legacy in LEGACY_KEYS.items():
        if legacy not in obj and low in obj:
            obj[legacy] = obj[low]

def enforce_profile_shape_legacy(obj: dict, profile: str) -> dict:
    """
    Contrato FINAL:
    guest:
      Diagnóstico Jurídico = null
      Fundamento Táctico = null
      Ruta de Blindaje = 3 pasos (objeto con paso_1, paso_2, paso_3)
      Riesgos y Consecuencias = null
      Formato de Emergencia = null
      Teléfono de contacto = null

    free:
      Diagnóstico Jurídico = objeto
      Fundamento Táctico = null
      Ruta de Blindaje = 3 pasos
      Riesgos y Consecuencias = null
      Formato de Emergencia = null
      Teléfono de contacto = null

    premium:
      todo puede ir (según aplique). No recortamos.
    """

    # 0) si viene algo en minúsculas, lo eliminamos para no mezclar contratos
    _drop_lowercase_keys_if_present(obj)

    # 1) Asegurar que existan las llaves legacy (si faltan, se crean)
    for k in ["Diagnóstico Jurídico", "Fundamento Táctico", "Ruta de Blindaje", "Riesgos y Consecuencias", "Formato de Emergencia", "Teléfono de contacto"]:
        if k not in obj:
            obj[k] = None

    # 2) Forzado por perfil
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

        # Si por error el modelo puso null, lo dejamos como viene, pero idealmente debe ser objeto.
        # (Si quieres strict: si viene null => 502)
        # comment

    else:
        # premium: no recortamos; si no aplica FE/teléfono, puede ser null.
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
            config=types.GenerateContentConfig(
                cached_content=cache.name
            ),
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

    _upgrade_lowercase_to_legacy(obj)
    _drop_lowercase_keys_if_present(obj)
    obj = enforce_profile_shape_legacy(obj, pol.profile)

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