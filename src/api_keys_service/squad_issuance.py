"""Reconcile exactly one Squad statement-source credential under deployment authority."""

import asyncio
from dataclasses import dataclass
import hashlib
import json
import os
import re
import uuid

import jwt
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, SecretStr, field_validator
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from api.infrastructure.persistence.db_session import get_db_session
from api_keys_service import authority
from api_keys_service.account_lifecycle import require_owner_open
from api_keys_service.crypto import hash_secret, verify_secret
from api_keys_service.fingerprint import renter_key_fingerprint
from controlplane_db.models import ApiKey


SCOPES = ("acl:statements:read", "acl:statements:write")


@dataclass(frozen=True)
class SquadBinding:
    environment: str
    tenant: uuid.UUID
    subject: str
    workflow_ref: str
    repository_id: str
    owner_id: str
    operation: str

    @property
    def name(self) -> str:
        plane = "test" if self.environment == "test" else "prod"
        return f"s3rch-{plane}-squad-statement-source-key-{self.operation}"


def configured_binding() -> SquadBinding:
    raw = os.environ.get("API_KEYS_SQUAD_DEPLOYMENT_BINDING")
    if raw is None or not authority.enabled():
        raise HTTPException(404, "Squad deployment issuance unavailable")
    try:
        value = json.loads(raw)
        binding = SquadBinding(**{**value, "tenant": uuid.UUID(value["tenant"])})
        if (binding.environment not in {"test", "production"}
                or not re.fullmatch(r"FyberLabs/infra/\.github/workflows/[a-z0-9-]+\.yml@refs/heads/main",
                                    binding.workflow_ref)
                or not all(re.fullmatch(r"[1-9][0-9]{0,19}", item)
                           for item in (binding.repository_id, binding.owner_id))
                or str(uuid.UUID(binding.subject)) != binding.subject
                or not re.fullmatch(r"[a-f0-9]{32}", binding.operation)):
            raise ValueError()
    except (KeyError, TypeError, ValueError, AttributeError):
        raise HTTPException(503, "Squad deployment binding invalid") from None
    return binding


def require_deployment_claims(claims: dict, binding: SquadBinding) -> None:
    expected = {
        "aud": f"spanopticon:squad-statement-issuance:{binding.environment}",
        "repository": "FyberLabs/infra",
        "repository_id": binding.repository_id,
        "repository_owner_id": binding.owner_id,
        "environment": binding.environment,
        "sub": f"repo:FyberLabs/infra:environment:{binding.environment}",
        "ref": "refs/heads/main",
        "workflow_ref": binding.workflow_ref,
    }
    if any(claims.get(name) != value for name, value in expected.items()):
        raise HTTPException(403, "Squad deployment identity refused")
    if claims.get("job_workflow_ref", binding.workflow_ref) != binding.workflow_ref:
        raise HTTPException(403, "Squad deployment identity refused")


async def reconcile(
    session: AsyncSession, binding: SquadBinding, credential: str | None,
) -> dict[str, str | None]:
    selection = authority.configured_selection({
        "tenant_id": binding.tenant, "organization_id": None, "network_id": "s3r.ch",
        "scope_kind": "network", "owner_sub": binding.subject,
    })
    await authority.authorize(selection, "mint", purpose="service", scopes=SCOPES)
    await require_owner_open(session, binding.tenant, binding.subject)

    # Serialize even when there is no candidate row to lock yet.
    lock = int.from_bytes(hashlib.sha256(
        f"squad-statement:{binding.tenant}:{binding.name}".encode()
    ).digest()[:8], "big", signed=True)
    await session.execute(text("SELECT pg_advisory_xact_lock(:lock)"), {"lock": lock})
    result = await session.execute(select(ApiKey).where(
        ApiKey.tenant_id == binding.tenant,
        ApiKey.name == binding.name,
        ApiKey.revoked_at.is_(None),
    ).limit(2))
    rows = list(result.scalars())
    if len(rows) > 1:
        raise HTTPException(409, "Squad credential inventory ambiguous")
    if rows:
        row = rows[0]
        owner = await authority.key_binding(session, row)
        if (row.created_by_sub != binding.subject or row.purpose != "service"
                or tuple(row.scopes or ()) != SCOPES or not owner
                or owner["network_id"] != "s3r.ch" or owner["scope_kind"] != "network"
                or owner["organization_id"] is not None):
            raise HTTPException(409, "Squad credential ownership differs")
        if credential is not None:
            prefix, secret = credential.split(".", 1)
            if row.key_prefix != prefix or not verify_secret(secret, row.secret_hash):
                raise HTTPException(409, "Squad credential value differs")
        return {"state": "active", "key_id": str(row.id)}
    if credential is None:
        return {"state": "absent", "key_id": None}

    prefix, secret = credential.split(".", 1)
    row = ApiKey(tenant_id=binding.tenant, key_prefix=prefix, secret_hash=hash_secret(secret),
                 name=binding.name, scopes=list(SCOPES), created_by_sub=binding.subject,
                 purpose="service", key_fingerprint=renter_key_fingerprint(credential))
    session.add(row)
    try:
        await session.flush()
        await authority.bind(session, row, selection)
    except Exception:
        await session.rollback()
        raise
    return {"state": "active", "key_id": str(row.id)}


class SquadCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credential: SecretStr | None = None

    @field_validator("credential")
    @classmethod
    def bounded_credential(cls, value):
        if value is not None and not re.fullmatch(
            r"[a-f0-9]{16}\.[A-Za-z0-9_-]{43}", value.get_secret_value()
        ):
            raise ValueError("invalid Squad candidate format")
        return value


def verify_deployment_token(token: str, binding: SquadBinding) -> None:
    issuer = "https://token.actions.githubusercontent.com"
    try:
        key = _github_keys.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token, key, algorithms=["RS256"], issuer=issuer,
            audience=f"spanopticon:squad-statement-issuance:{binding.environment}",
            options={"require": ["exp", "iat", "nbf", "iss", "aud", "sub"], "strict_aud": True},
        )
    except jwt.PyJWKClientConnectionError:
        raise HTTPException(503, "Squad issuer verification unavailable") from None
    except jwt.PyJWTError:
        raise HTTPException(401, "Squad issuer token refused") from None
    require_deployment_claims(claims, binding)


_github_keys = jwt.PyJWKClient(
    "https://token.actions.githubusercontent.com/.well-known/jwks", timeout=5,
)
router = APIRouter()


@router.put("/internal/squad-statement-credential", include_in_schema=False)
async def reconcile_squad_credential(
    request: Request,
    candidate: SquadCandidate,
    authorization: str | None = Header(None),
    session: AsyncSession = Depends(get_db_session),
):
    binding = configured_binding()
    if request.state.tenant_id != binding.tenant:
        raise HTTPException(403, "Squad deployment tenant refused")
    if (authorization is None or len(authorization) > 16384
            or not authorization.startswith("Bearer ")):
        raise HTTPException(401, "Squad issuer token required")
    await asyncio.to_thread(verify_deployment_token, authorization[7:], binding)
    credential = candidate.credential.get_secret_value() if candidate.credential is not None else None
    result = await reconcile(session, binding, credential)
    return JSONResponse(result, headers={"Cache-Control": "no-store"})
