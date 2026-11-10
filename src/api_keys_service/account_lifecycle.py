"""Owner-scoped key revocation, serialized with key minting."""

from __future__ import annotations

import uuid
from datetime import datetime

from api.infrastructure.persistence.db_session import get_db_session
from controlplane_db.models import ApiKey, ApiKeyOwnerClosure
from controlplane_identity.account_lifecycle import (
    authorized_call,
    enforcement_enabled,
    require_closure_permit,
)
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, text, update
from api_keys_service import authority
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(prefix="/api-keys/internal")


async def owner_lock(session: AsyncSession, tenant: uuid.UUID, subject: str) -> None:
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"api-key-owner:{tenant}:{subject}"},
    )


async def require_owner_open(
    session: AsyncSession, tenant: uuid.UUID, subject: str
) -> None:
    if not enforcement_enabled():
        return
    await owner_lock(session, tenant, subject)
    if await session.get(ApiKeyOwnerClosure, (tenant, subject)) is not None:
        raise HTTPException(403, "Account is unavailable")


class KeyStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key_id: uuid.UUID


class CloseOwner(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: str = Field(min_length=1, max_length=512)
    closed_at: datetime


def tenant(request: Request) -> uuid.UUID:
    value = getattr(request.state, "tenant_id", None)
    if value is None:
        raise HTTPException(400, "X-Tenant-ID required")
    return value


@router.post("/account-status")
async def account_status(
    request: Request,
    response: Response,
    body: KeyStatus,
    session: AsyncSession = Depends(get_db_session),
):
    response.headers["Cache-Control"] = "no-store"
    if not authorized_call(request.headers):
        raise HTTPException(403, "Account lifecycle authority required")
    tid = tenant(request)
    row = (
        await session.execute(
            select(ApiKey).where(ApiKey.tenant_id == tid, ApiKey.id == body.key_id)
        )
    ).scalar_one_or_none()
    if (
        row is None
        or row.revoked_at is not None
        or not row.created_by_sub
        or row.created_by_sub.startswith("apikey:")
    ):
        return {"blocked": True}
    # The principal tombstone blocks sessions during retries even before this
    # owner's local revocation receipt has been acknowledged.
    import asyncio

    from controlplane_identity.account_lifecycle import require_open_account
    from jwt import InvalidTokenError

    try:
        await asyncio.to_thread(
            require_open_account, {"sub": row.created_by_sub, "tenant_id": str(tid)}
        )
    except InvalidTokenError:
        return {"blocked": True}
    return {
        "blocked": await session.get(ApiKeyOwnerClosure, (tid, row.created_by_sub))
        is not None
    }


@router.post("/close-owner")
async def close_owner(
    request: Request,
    response: Response,
    body: CloseOwner,
    session: AsyncSession = Depends(get_db_session),
):
    response.headers["Cache-Control"] = "no-store"
    if not authorized_call(request.headers, mutation=True):
        raise HTTPException(403, "Account lifecycle authority required")
    tid = tenant(request)
    if not body.subject.strip() or body.subject.startswith("apikey:"):
        raise HTTPException(422, "Exact account subject required")
    try:
        await require_closure_permit(
            subject=body.subject, closed_at=body.closed_at, tenant_id=tid
        )
    except RuntimeError:
        raise HTTPException(503, "Account closure permit unavailable") from None
    await owner_lock(session, tid, body.subject)
    await session.execute(
        insert(ApiKeyOwnerClosure)
        .values(
            tenant_id=tid,
            subject=body.subject,
            closed_at=body.closed_at,
        )
        .on_conflict_do_nothing(index_elements=["tenant_id", "subject"])
    )
    marker = await session.get(ApiKeyOwnerClosure, (tid, body.subject))
    if marker.closed_at != body.closed_at:
        raise HTTPException(409, "Closure timestamp conflicts with original receipt")
    await session.execute(
        update(ApiKey)
        .where(
            ApiKey.tenant_id == tid,
            ApiKey.created_by_sub == body.subject,
            ApiKey.revoked_at.is_(None),
        )
        .values(revoked_at=body.closed_at)
    )
    rows = (
        (
            await session.execute(
                select(ApiKey)
                .where(
                    ApiKey.tenant_id == tid,
                    ApiKey.created_by_sub == body.subject,
                )
                .order_by(ApiKey.id)
            )
        )
        .scalars()
        .all()
    )
    # Repeat the same inventory after a lost response. The coordinator must
    # durably deliver every fingerprint to the Hypermesh/gateway owners before
    # acknowledging full retirement. Never return key secrets or secret hashes.
    return {
        "keys": [
            {
                "id": str(row.id),
                "fingerprint": row.key_fingerprint,
                "purpose": row.purpose or "renter",
            }
            for row in rows
        ]
    }


@router.post("/owner-inventory")
async def owner_inventory(
    request: Request,
    response: Response,
    body: CloseOwner,
    session: AsyncSession = Depends(get_db_session),
):
    """Discover exact-subject credentials even without a directory membership."""
    response.headers["Cache-Control"] = "no-store"
    if not authorized_call(request.headers, mutation=True):
        raise HTTPException(403, "Account lifecycle authority required")
    if not body.subject.strip() or body.subject.startswith("apikey:"):
        raise HTTPException(422, "Exact account subject required")
    try:
        await require_closure_permit(
            subject=body.subject, closed_at=body.closed_at, tenant_id=None
        )
    except RuntimeError:
        raise HTTPException(503, "Account closure permit unavailable") from None
    if authority.enabled():
        rows = (await session.execute(text(
            "SELECT id,tenant_id,key_fingerprint,purpose FROM api_key_subject_inventory(:subject) LIMIT 100001"
        ),{'subject':body.subject})).all()
    else:
        rows = list(
    
                await session.scalars(
                    select(ApiKey)
                    .where(ApiKey.created_by_sub == body.subject)
                    .order_by(ApiKey.tenant_id, ApiKey.id)
                    .limit(100_001)
                )
    
        )
    if len(rows) > 100_000:
        raise HTTPException(503, "Account key inventory exceeds limit")
    return {
        "keys": [
            {
                "tenant_id": str(row.tenant_id),
                "id": str(row.id),
                "fingerprint": row.key_fingerprint,
                "purpose": row.purpose or "renter",
            }
            for row in rows
        ]
    }


@router.post("/purge-owner")
async def purge_owner(
    request: Request,
    response: Response,
    body: CloseOwner,
    session: AsyncSession = Depends(get_db_session),
):
    from controlplane_identity.account_lifecycle import closure_scope
    from sqlalchemy import delete

    response.headers["Cache-Control"] = "no-store"
    if not authorized_call(request.headers, mutation=True):
        raise HTTPException(403, "Account lifecycle authority required")
    tid = tenant(request)
    if not body.subject.strip() or body.subject.startswith("apikey:"):
        raise HTTPException(422, "Exact account subject required")
    try:
        scope = await closure_scope(
            subject=body.subject, closed_at=body.closed_at, tenant_id=tid
        )
    except RuntimeError:
        raise HTTPException(503, "Account erasure permit unavailable") from None
    if not scope["erasure_allowed"] or not scope["keys_complete"]:
        raise HTTPException(409, "Account key erasure is not yet authorized")
    await owner_lock(session, tid, body.subject)
    marker = await session.get(
        ApiKeyOwnerClosure, (tid, body.subject), populate_existing=True
    )
    if marker is None or marker.closed_at != body.closed_at:
        raise HTTPException(409, "Original key closure receipt required")
    rows = list(
        await session.scalars(
            select(ApiKey)
            .where(ApiKey.tenant_id == tid, ApiKey.created_by_sub == body.subject)
            .with_for_update()
        )
    )
    expected = {uuid.UUID(key["id"]) for key in scope["keys"]}
    if any(row.id not in expected or row.revoked_at is None for row in rows):
        raise HTTPException(409, "Closed key inventory does not match its receipt")
    removed = await session.execute(
        delete(ApiKey).where(
            ApiKey.tenant_id == tid, ApiKey.created_by_sub == body.subject
        )
    )
    return {"deleted": removed.rowcount, "remaining": 0}
