"""Publish a renter key fingerprint to Hypermesh at mint. Not the chat path."""

from __future__ import annotations

import hashlib
import logging
import os
import uuid
from collections.abc import Awaitable, Callable

import httpx

from api.core.config import settings

logger = logging.getLogger(__name__)

FingerprintPublisher = Callable[[uuid.UUID, str], Awaitable[None]]


def renter_key_fingerprint(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


async def publish_renter_key_fingerprint(
    tenant_id: uuid.UUID,
    fingerprint: str,
    *,
    publisher: FingerprintPublisher | None = None,
) -> None:
    if publisher is not None:
        await publisher(tenant_id, fingerprint)
        return
    base = (os.environ.get("HYPERMESH_CONTROL_PLANE_URL") or "").strip()
    token = (settings.hypermesh_internal_token or "").strip()
    if not base or not token:
        return
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                f"{base.rstrip('/')}/api/v1/hypermesh/internal/renter-key-fingerprints",
                headers={
                    "X-Internal-Token": token,
                    "X-Tenant-ID": str(tenant_id),
                },
                json={"fingerprint": fingerprint},
            )
        if response.status_code >= 400:
            logger.info("renter key fingerprint publish refused")
    except Exception:
        logger.info("renter key fingerprint publish skipped")
