# backend/app/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.endpoints import router
from app.models.database import Base, engine, create_default_admin
from app.core.scheduler import start_scheduler

app = FastAPI(title="NetMon API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # temporaire pour production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    create_default_admin()
    start_scheduler()

app.include_router(router, prefix="/api")