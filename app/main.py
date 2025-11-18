from fastapi import FastAPI
from app.controllers.user_controller import user_router
from app.core.lifespan import lifespan

app = FastAPI(
    title="E-Commerce",
    lifespan=lifespan
)

app.include_router(user_router, prefix="/fastapi/app")
