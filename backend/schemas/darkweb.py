from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class DarkWebWatchlistIn(BaseModel):
    tenant_id: str
    watch_type: str
    watch_value: str
    label: str | None = None
    severity: str = "medium"


class DarkWebSourceItemIn(BaseModel):
    tenant_id: str
    source_ref: str
    source_name: str | None = None
    source_type: str | None = None
    title: str | None = None
    content_text: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class DarkWebRunRequest(BaseModel):
    tenant_id: str
