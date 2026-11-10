"""Publish a renter key fingerprint to Hypermesh at mint. Not the chat path."""

from __future__ import annotations

import hashlib
import logging
import os
import uuid
from collections.abc import Awaitable, Callable

import httpx

from controlplane_api.config import settings

logger = logging.getLogger(__name__)

FingerprintPublisher = Callable[[uuid.UUID, str], Awaitable[None]]


class FingerprintRevokeError(Exception):
    """The plane did not unpublish the fingerprint. Revoke must not succeed."""


def renter_key_fingerprint(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


async def revoke_renter_key_fingerprint(
    tenant_id: uuid.UUID,
    fingerprint: str,
    *,
    purpose: str = "renter",
    publisher: FingerprintPublisher | None = None,
) -> None:
    """Unpublish a fingerprint. IR keys are dropped from both sets.

    Mint publishes renter fingerprints for every purpose today, and IR keys
    may also be filed on the IR set. Revoke clears the set the door reads.
    """

    if not fingerprint:
        raise FingerprintRevokeError("fingerprint unpublish failed")
    if publisher is not None:
        try:
            await publisher(tenant_id, fingerprint)
        except Exception as exc:
            raise FingerprintRevokeError("fingerprint unpublish failed") from exc
        return
    base = (os.environ.get("HYPERMESH_CONTROL_PLANE_URL") or "").strip()
    token = (settings.hypermesh_internal_token or "").strip()
    if not base or not token:
        raise FingerprintRevokeError("fingerprint unpublish is not configured")
    paths = ["renter-key-fingerprints/revoke"]
    if purpose == "ir":
        paths.append("ir-key-fingerprints/revoke")
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            for path in paths:
                response = await client.post(
                    f"{base.rstrip('/')}/api/v1/hypermesh/internal/{path}",
                    headers={
                        "X-Internal-Token": token,
                        "X-Tenant-ID": str(tenant_id),
                    },
                    json={"fingerprint": fingerprint},
                )
                if not 200 <= response.status_code < 300:
                    raise FingerprintRevokeError(
                        f"fingerprint unpublish refused ({response.status_code})"
                    )
    except FingerprintRevokeError:
        raise
    except Exception as exc:
        raise FingerprintRevokeError("fingerprint unpublish failed") from exc


async def fetch_mapped_lease(tenant_id: uuid.UUID) -> dict[str, str | None] | None:
    """Ask the plane which active lease a tenant key maps to. None if unknown."""

    base = (os.environ.get("HYPERMESH_CONTROL_PLANE_URL") or "").strip()
    token = (settings.hypermesh_internal_token or "").strip()
    if not base or not token:
        return None
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(
                f"{base.rstrip('/')}/api/v1/hypermesh/internal/mapped-lease",
                headers={
                    "X-Internal-Token": token,
                    "X-Tenant-ID": str(tenant_id),
                },
            )
    except Exception:
        logger.info("mapped lease lookup skipped")
        return None
    if response.status_code != 200:
        return None
    body = response.json()
    if not isinstance(body, dict) or not body.get("lease_id"):
        return None
    catalog = body.get("catalog_id")
    return {
        "lease_id": str(body["lease_id"]),
        "catalog_id": str(catalog) if catalog else None,
    }


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
