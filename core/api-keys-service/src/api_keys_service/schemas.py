from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, Field


class ApiKeyCreateRequest(BaseModel):
    name: str | None = Field(default=None, max_length=256)
    scopes: list[str] = Field(default_factory=list)


class ApiKeyResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    key_prefix: str
    name: str | None
    scopes: list[str]
    created_at: str
    revoked_at: str | None = None


class ApiKeyCreatedResponse(ApiKeyResponse):
    """Plaintext secret shown once."""

    secret_plaintext: str = Field(
        ...,
        description="Full key prefix.secret — store securely; never shown again.",
    )
    api_key: str = Field(..., description="Alias for prefix.secret")


class InternalValidateRequest(BaseModel):
    api_key: str = Field(..., min_length=8, description="key_prefix.secret")
    tenant_id: uuid.UUID


class InternalValidateResponse(BaseModel):
    valid: bool
    key_id: uuid.UUID | None = None
    tenant_id: uuid.UUID | None = None
    scopes: list[str] = Field(default_factory=list)
