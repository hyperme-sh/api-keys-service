"""Publish a renter key fingerprint to Hypermesh at mint. Not the chat path."""

from __future__ import annotations

import hashlib
import logging
import os
import ssl
from urllib.parse import urlsplit
import uuid
from collections.abc import Awaitable, Callable

import httpx

from controlplane_api.config import settings
from api_keys_service import authority

logger = logging.getLogger(__name__)

FingerprintPublisher = Callable[[uuid.UUID, str], Awaitable[None]]


def _client_options(base):
    if not authority.enabled():return {'timeout':5.0}
    url=urlsplit(base.rstrip('/'))
    if url.scheme!='https' or not url.hostname or url.username or url.password or url.path or url.query or url.fragment:
        raise ValueError('Verified fingerprint owner HTTPS origin required')
    return dict(timeout=5.0,trust_env=False,follow_redirects=False,
        verify=ssl.create_default_context(cafile=os.environ.get('API_KEYS_FINGERPRINT_CA_FILE') or None))


class FingerprintPublishError(Exception):
    """The required owner did not acknowledge the fingerprint."""


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
    token = authority.credential("API_KEYS_FINGERPRINT_TOKEN_FILE") if authority.enabled() else (settings.hypermesh_internal_token or "").strip()
    if not base or not token:
        raise FingerprintRevokeError("fingerprint unpublish is not configured")
    paths = ["renter-key-fingerprints/revoke"]
    if purpose == "ir":
        paths.append("ir-key-fingerprints/revoke")
    try:
        async with httpx.AsyncClient(**_client_options(base)) as client:
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
    token = authority.credential("API_KEYS_FINGERPRINT_TOKEN_FILE") if authority.enabled() else (settings.hypermesh_internal_token or "").strip()
    if not base or not token:
        return None
    try:
        async with httpx.AsyncClient(**_client_options(base)) as client:
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
    purpose: str = "renter",
    required: bool = False,
) -> None:
    if publisher is not None and not required:
        await publisher(tenant_id,fingerprint)
        return
    try:
        if publisher is not None:
            await publisher(tenant_id, fingerprint)
            return
        base = (os.environ.get("HYPERMESH_CONTROL_PLANE_URL") or "").strip()
        token = authority.credential("API_KEYS_FINGERPRINT_TOKEN_FILE") if authority.enabled() else (settings.hypermesh_internal_token or "").strip()
        if not base or not token:
            if required:raise FingerprintPublishError("Fingerprint owner unavailable")
            return
        path = "ir-key-fingerprints" if required and purpose == "ir" else "renter-key-fingerprints"
        async with httpx.AsyncClient(**_client_options(base)) as client:
            response = await client.post(
                f"{base.rstrip('/')}/api/v1/hypermesh/internal/{path}",
                headers={"X-Internal-Token":token,"X-Tenant-ID":str(tenant_id)},
                json={"fingerprint":fingerprint},
            )
        if not 200 <= response.status_code < 300:
            if required:raise FingerprintPublishError("Fingerprint owner refused")
            logger.info("renter key fingerprint publish refused")
    except Exception as error:
        if required:raise FingerprintPublishError("Fingerprint owner unavailable") from None
        logger.info("renter key fingerprint publish skipped")
