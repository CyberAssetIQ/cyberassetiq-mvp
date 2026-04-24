from __future__ import annotations

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models.mixins import Base
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./cyberassetiq.db",
)

engine_kwargs: dict = {"future": True, "pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **engine_kwargs)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    future=True
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
