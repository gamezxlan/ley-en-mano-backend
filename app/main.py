import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi import _rate_limit_exceeded_handler
from .ratelimit import limiter
from .routes import router
from .cache import create_caches

ENV = os.getenv("ENV", "development")

if ENV == "production":
    ALLOWED_ORIGINS = [
        "https://leyenmano.com",
        "https://www.leyenmano.com",
    ]
else:
    ALLOWED_ORIGINS = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
    ]

app = FastAPI(title="Ley en Mano")

# ===============================
# 🔐 CORS DINÁMICO
# ===============================
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=[
        "Content-Type"
    ],
)

# ===============================
# 🔒 RATE LIMIT
# ===============================
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ===============================
# ⚖️ CACHE LEGAL
# ===============================
@app.on_event("startup")
def startup():
    create_caches()

# ===============================
# 🚦 ROUTES
# ===============================
app.include_router(router)