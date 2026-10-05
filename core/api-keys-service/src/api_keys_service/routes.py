from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.common.internal_token import internal_token_matches
from api.core.config import settings
from api.infrastructure.persistence.db_session import get_db_session
from auth_service.deps import CurrentUser, get_access_token_claims, get_current_tenant
from controlplane_db.models import ApiKey

from api_keys_service.allowlist import (
    IR_MINT_REFUSED,
    MINT_REFUSED,
    actor_can_mint_keys,
    actor_controls,
    is_smoke_session,
    smoke_may_mint,
    smoke_owns_key,
)
from api_keys_service.crypto import hash_secret, verify_secret
from api_keys_service.fingerprint import (
    FingerprintRevokeError,
    fetch_mapped_lease,
    publish_renter_key_fingerprint,
    renter_key_fingerprint,
    revoke_renter_key_fingerprint,
)
from api_keys_service.schemas import (
    ApiKeyCreatedResponse,
    ApiKeyCreateRequest,
    ApiKeyMappedLease,
    ApiKeyRenameRequest,
    ApiKeyResponse,
    InternalTouchRequest,
    InternalValidateRequest,
    InternalValidateResponse,
)

router = APIRouter(tags=["api-keys"])


async def require_matched_tenant(
    request: Request,
    tenant: uuid.UUID = Depends(get_current_tenant),
) -> uuid.UUID:
    raw = request.headers.get("X-Tenant-ID")
    if not raw:
        raise HTTPException(status_code=400, detail="X-Tenant-ID header is required")
    try:
        hdr = uuid.UUID(str(raw))
    except ValueError as e:
        raise HTTPException(status_code=400, detail="Invalid X-Tenant-ID") from e
    if hdr != tenant:
        raise HTTPException(status_code=403, detail="X-Tenant-ID must match tenant in access token")
    return tenant


def _scopes_list(raw: list | None) -> list[str]:
    if not raw:
        return []
    return [str(x) for x in raw]


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat()


def _key_response(row: ApiKey, mapped: ApiKeyMappedLease | None) -> ApiKeyResponse:
    lease = None if row.revoked_at is not None else mapped
    return ApiKeyResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        key_prefix=row.key_prefix,
        name=row.name,
        scopes=_scopes_list(row.scopes),
        created_at=row.created_at.isoformat(),
        revoked_at=_iso(row.revoked_at),
        purpose=getattr(row, "purpose", None) or "renter",
        last_used_at=_iso(getattr(row, "last_used_at", None)),
        mapped_lease=lease,
    )


async def _mapped_lease(request: Request, tenant_id: uuid.UUID) -> ApiKeyMappedLease | None:
    hook = getattr(getattr(request.app, "state", None), "mapped_lease_lookup", None)
    raw = await hook(tenant_id) if hook is not None else await fetch_mapped_lease(tenant_id)
    if not raw or not raw.get("lease_id"):
        return None
    return ApiKeyMappedLease(
        lease_id=uuid.UUID(str(raw["lease_id"])),
        catalog_id=raw.get("catalog_id"),
    )


@router.post("/api-keys", response_model=ApiKeyCreatedResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    request: Request,
    user: CurrentUser,
    body: ApiKeyCreateRequest,
    _: uuid.UUID = Depends(require_matched_tenant),
    session: AsyncSession = Depends(get_db_session),
    claims: dict | None = Depends(get_access_token_claims),
) -> ApiKeyCreatedResponse:
    tid = request.state.tenant_id
    if tid is None:
        raise HTTPException(status_code=400, detail="X-Tenant-ID required")
    if not smoke_may_mint(claims, body.purpose, body.scopes or []):
        raise HTTPException(
            status_code=403,
            detail="smoke session may only mint a renter key",
        )
    controls = await actor_controls(session, tid, user)
    if body.purpose == "ir":
        if not controls.can_use_ir_door:
            raise HTTPException(status_code=403, detail=IR_MINT_REFUSED)
    elif not controls.can_mint_keys:
        raise HTTPException(status_code=403, detail=MINT_REFUSED)

    prefix = secrets.token_hex(8)
    secret = secrets.token_urlsafe(32)
    full = f"{prefix}.{secret}"
    row = ApiKey(
        tenant_id=tid,
        key_prefix=prefix,
        secret_hash=hash_secret(secret),
        name=body.name,
        scopes=body.scopes or [],
        created_by_sub=str(user.email) if user.email else None,
        purpose=body.purpose,
        key_fingerprint=renter_key_fingerprint(full),
    )
    session.add(row)
    await session.flush()
    await session.refresh(row)
    publisher = getattr(getattr(request, "app", None), "state", None)
    hook = getattr(publisher, "renter_key_fingerprint_publisher", None) if publisher else None
    await publish_renter_key_fingerprint(
        tid, renter_key_fingerprint(full), publisher=hook
    )
    return ApiKeyCreatedResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        key_prefix=row.key_prefix,
        name=row.name,
        scopes=_scopes_list(row.scopes),
        created_at=row.created_at.isoformat(),
        revoked_at=None,
        secret_plaintext=secret,
        api_key=full,
        purpose=row.purpose or "renter",
    )


@router.get("/api-keys", response_model=list[ApiKeyResponse])
async def list_api_keys(
    request: Request,
    user: CurrentUser,
    _: uuid.UUID = Depends(require_matched_tenant),
    session: AsyncSession = Depends(get_db_session),
    claims: dict | None = Depends(get_access_token_claims),
) -> list[ApiKeyResponse]:
    tid = request.state.tenant_id
    if tid is None:
        raise HTTPException(status_code=400, detail="X-Tenant-ID required")
    q = await session.execute(
        select(ApiKey).where(ApiKey.tenant_id == tid).order_by(ApiKey.created_at.desc())
    )
    rows = q.scalars().all()
    if is_smoke_session(claims):
        rows = [
            row
            for row in rows
            if smoke_owns_key(claims, getattr(row, "created_by_sub", None), user.email)
        ]
    mapped = await _mapped_lease(request, tid)
    return [_key_response(row, mapped) for row in rows]


@router.delete("/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    key_id: uuid.UUID,
    request: Request,
    user: CurrentUser,
    _: uuid.UUID = Depends(require_matched_tenant),
    session: AsyncSession = Depends(get_db_session),
    claims: dict | None = Depends(get_access_token_claims),
) -> None:
    tid = request.state.tenant_id
    if tid is None:
        raise HTTPException(status_code=400, detail="X-Tenant-ID required")
    if not await actor_can_mint_keys(session, tid, user):
        raise HTTPException(status_code=403, detail=MINT_REFUSED)
    q = await session.execute(
        select(ApiKey).where(ApiKey.id == key_id, ApiKey.tenant_id == tid)
    )
    row = q.scalar_one_or_none()
    if row is None or not smoke_owns_key(
        claims, getattr(row, "created_by_sub", None), user.email
    ):
        raise HTTPException(status_code=404, detail="API key not found")
    fingerprint = getattr(row, "key_fingerprint", None)
    purpose = getattr(row, "purpose", None) or "renter"
    if fingerprint:
        publisher = getattr(getattr(request, "app", None), "state", None)
        hook = getattr(publisher, "renter_key_fingerprint_revoker", None) if publisher else None
        try:
            await revoke_renter_key_fingerprint(
                tid, fingerprint, purpose=purpose, publisher=hook
            )
        except FingerprintRevokeError as exc:
            raise HTTPException(
                status_code=502,
                detail="Could not unpublish the API key",
            ) from exc
    row.revoked_at = datetime.now(UTC)
    await session.flush()


@router.patch("/api-keys/{key_id}", response_model=ApiKeyResponse)
async def rename_api_key(
    key_id: uuid.UUID,
    request: Request,
    user: CurrentUser,
    body: ApiKeyRenameRequest,
    _: uuid.UUID = Depends(require_matched_tenant),
    session: AsyncSession = Depends(get_db_session),
    claims: dict | None = Depends(get_access_token_claims),
) -> ApiKeyResponse:
    tid = request.state.tenant_id
    if tid is None:
        raise HTTPException(status_code=400, detail="X-Tenant-ID required")
    if not await actor_can_mint_keys(session, tid, user):
        raise HTTPException(status_code=403, detail=MINT_REFUSED)
    q = await session.execute(
        select(ApiKey).where(ApiKey.id == key_id, ApiKey.tenant_id == tid)
    )
    row = q.scalar_one_or_none()
    if row is None or not smoke_owns_key(
        claims, getattr(row, "created_by_sub", None), user.email
    ):
        raise HTTPException(status_code=404, detail="API key not found")
    row.name = body.name
    await session.flush()
    return _key_response(row, await _mapped_lease(request, tid))


@router.post("/internal/touch", status_code=status.HTTP_204_NO_CONTENT)
async def internal_touch(
    body: InternalTouchRequest,
    x_internal_token: str | None = Header(None, alias="X-Internal-Token"),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    """Stamp last_used_at. The gateway throttles this to one write per minute."""

    if not internal_token_matches(x_internal_token, settings.usable_api_keys_internal_token()):
        raise HTTPException(status_code=401, detail="Invalid internal token")
    q = await session.execute(select(ApiKey).where(ApiKey.id == body.key_id))
    row = q.scalar_one_or_none()
    if row is None or row.revoked_at is not None:
        return
    row.last_used_at = datetime.now(UTC)
    await session.flush()


@router.post("/internal/validate", response_model=InternalValidateResponse)
async def internal_validate(
    body: InternalValidateRequest,
    x_internal_token: str | None = Header(None, alias="X-Internal-Token"),
    session: AsyncSession = Depends(get_db_session),
) -> InternalValidateResponse:
    if not internal_token_matches(x_internal_token, settings.usable_api_keys_internal_token()):
        raise HTTPException(status_code=401, detail="Invalid internal token")

    raw = body.api_key.strip()
    if "." not in raw:
        return InternalValidateResponse(valid=False)
    prefix, secret = raw.split(".", 1)
    if not prefix or not secret:
        return InternalValidateResponse(valid=False)

    q = await session.execute(select(ApiKey).where(ApiKey.key_prefix == prefix))
    row = q.scalar_one_or_none()
    if row is None or row.revoked_at is not None:
        return InternalValidateResponse(valid=False)
    if row.tenant_id != body.tenant_id:
        return InternalValidateResponse(valid=False)
    if not verify_secret(secret, row.secret_hash):
        return InternalValidateResponse(valid=False)

    return InternalValidateResponse(
        valid=True,
        key_id=row.id,
        tenant_id=row.tenant_id,
        scopes=_scopes_list(row.scopes),
        purpose=getattr(row, "purpose", None) or "renter",
    )