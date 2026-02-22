# app/auth_routes.py
from fastapi import APIRouter, Request, Response, HTTPException
import os, secrets, urllib.parse, requests
from .auth_repo import upsert_user_by_email, create_session

ENV = os.getenv("ENV", "development")
COOKIE_DOMAIN = os.getenv("COOKIE_DOMAIN", ".leyenmano.com" if ENV == "production" else None)
SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "session_id")

GOOGLE_CLIENT_ID = os.environ["GOOGLE_OAUTH_CLIENT_ID"]
GOOGLE_CLIENT_SECRET = os.environ["GOOGLE_OAUTH_CLIENT_SECRET"]
GOOGLE_REDIRECT_URI = os.environ["GOOGLE_OAUTH_REDIRECT_URI"]
FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "http://localhost:5173")

router = APIRouter(prefix="/auth", tags=["auth"])

def _set_session_cookie(response: Response, session_id: str):
    kwargs = dict(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        secure=(ENV == "production"),
        samesite="lax",   # ✅ recomendado si frontend y api están en el mismo “site” (leyenmano.com)
        max_age=60 * 60 * 24 * 14,
        path="/",
    )
    if COOKIE_DOMAIN:
        kwargs["domain"] = COOKIE_DOMAIN
    response.set_cookie(**kwargs)

def _set_state_cookie(response: Response, state: str):
    # cookie temporal solo para validar callback
    kwargs = dict(
        key="oauth_state",
        value=state,
        httponly=True,
        secure=(ENV == "production"),
        samesite="lax",
        max_age=60 * 10,
        path="/",
    )
    if COOKIE_DOMAIN:
        kwargs["domain"] = COOKIE_DOMAIN
    response.set_cookie(**kwargs)

def _get_state_cookie(request: Request) -> str | None:
    v = request.cookies.get("oauth_state")
    return v.strip() if v else None

def _clear_state_cookie(response: Response):
    kwargs = dict(key="oauth_state", path="/")
    if COOKIE_DOMAIN:
        kwargs["domain"] = COOKIE_DOMAIN
    response.delete_cookie(**kwargs)

@router.get("/google/start")
def google_start(response: Response):
    state = secrets.token_urlsafe(32)
    _set_state_cookie(response, state)

    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "prompt": "select_account",
        "access_type": "online",
    }
    url = "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params)
    response.status_code = 307
    response.headers["Location"] = url
    return

@router.get("/google/callback")
def google_callback(request: Request, response: Response, code: str | None = None, state: str | None = None, error: str | None = None):
    if error:
        # regresa al frontend con error
        response.status_code = 307
        response.headers["Location"] = f"{FRONTEND_BASE_URL}/?auth=error&reason={urllib.parse.quote(error)}"
        return

    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code/state")

    cookie_state = _get_state_cookie(request)
    if not cookie_state or cookie_state != state:
        raise HTTPException(status_code=400, detail="Invalid state")

    # intercambiar code por tokens
    token_resp = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": GOOGLE_REDIRECT_URI,
        },
        timeout=20,
    )
    if token_resp.status_code != 200:
        raise HTTPException(status_code=502, detail="Token exchange failed")

    tokens = token_resp.json()
    access_token = tokens.get("access_token")
    if not access_token:
        raise HTTPException(status_code=502, detail="No access_token")

    # obtener userinfo (email)
    userinfo = requests.get(
        "https://www.googleapis.com/oauth2/v3/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=20,
    )
    if userinfo.status_code != 200:
        raise HTTPException(status_code=502, detail="Userinfo failed")

    info = userinfo.json()
    email = (info.get("email") or "").strip().lower()
    if not email:
        raise HTTPException(status_code=400, detail="No email")

    # crear/obtener user
    user_id = upsert_user_by_email(email)

    # crear session y set cookie
    session_id = create_session(user_id, days=14)
    _set_session_cookie(response, session_id)
    _clear_state_cookie(response)

    # redirigir al frontend
    response.status_code = 307
    response.headers["Location"] = f"{FRONTEND_BASE_URL}/?auth=ok"
    return