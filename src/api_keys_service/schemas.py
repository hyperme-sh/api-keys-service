from __future__ import annotations

import uuid
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

KeyMintPurpose = Literal["renter", "ir", "service"]


class ApiKeyCreateRequest(BaseModel):
    name: str | None = Field(default=None, max_length=256)
    scopes: list[str] = Field(default_factory=list)
    purpose: KeyMintPurpose = "renter"

    @field_validator("purpose", mode="before")
    @classmethod
    def _purpose_renter_or_service(cls, value: object) -> str:
        if value is None or value == "":
            return "renter"
        raw = str(value).strip().lower()
        if raw in {"named service account", "service_account", "service-account"}:
            raw = "service"
        if raw not in {"renter", "ir", "service"}:
            raise ValueError("purpose must be renter, ir, or service")
        return raw


class ApiKeyMappedLease(BaseModel):
    """Lease this tenant-owned key would hit with no model override."""

    lease_id: uuid.UUID
    catalog_id: str | None = None


class ApiKeyRenameRequest(BaseModel):
    name: str | None = Field(default=None, max_length=256)


class ApiKeyResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    key_prefix: str
    name: str | None
    scopes: list[str]
    created_at: str
    revoked_at: str | None = None
    purpose: KeyMintPurpose = "renter"
    last_used_at: str | None = None
    mapped_lease: ApiKeyMappedLease | None = None


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
    purpose: KeyMintPurpose | None = None


class InternalTouchRequest(BaseModel):
    key_id: uuid.UUID
