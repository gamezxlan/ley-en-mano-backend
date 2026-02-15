from fastapi import FastAPI
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi import _rate_limit_exceeded_handler
from .ratelimit import limiter
from .routes import router
from .cache import create_cache

app = FastAPI(title="Ley en Mano")

# 🔒 RATE LIMIT
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.on_event("startup")
def startup():
    create_cache()


app.include_router(router)