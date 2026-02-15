from fastapi import FastAPI
from .cache import create_cache
from .routes import router

app = FastAPI(title="Ley en Mano")

@app.on_event("startup")
def startup():
    create_cache()

app.include_router(router)