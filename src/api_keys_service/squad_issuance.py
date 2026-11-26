"""Reconcile scoped s3r.ch service credentials under deployment authority."""

import asyncio
from dataclasses import dataclass
import hashlib
import json
import os
import re
import uuid

import jwt
from jwt.exceptions import PyJWKClientConnectionError
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, SecretStr
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from api.infrastructure.persistence.db_session import get_db_session
from api_keys_service import authority
from api_keys_service.account_lifecycle import require_owner_open
from api_keys_service.crypto import hash_secret, verify_secret
from api_keys_service.fingerprint import renter_key_fingerprint
from controlplane_db.models import ApiKey


SCOPES = ("acl:statements:read", "acl:statements:write")
CONTACTS_SCOPES = ("acl:contacts:read", "acl:contacts:write")
WORKFLOW_REF = re.compile(r"FyberLabs/infra/\.github/workflows/[a-z0-9-]+\.yml@refs/heads/main")
CONTACTS_TENANT = uuid.UUID("afee9b29-1706-5590-bbbf-e58df8945ac0")


@dataclass(frozen=True)
class SquadBinding:
    environment: str
    tenant: uuid.UUID
    subject: str
    workflow_ref: str
    repository_id: str
    owner_id: str
    operation: str
    contacts: bool = False
    job_workflow_ref: str | None = None

    @property
    def scopes(self) -> tuple[str, ...]:
        return CONTACTS_SCOPES if self.contacts else SCOPES

    @property
    def audience(self) -> str:
        purpose = "contacts" if self.contacts else "squad-statement"
        return f"spanopticon:{purpose}-issuance:{self.environment}"

    @property
    def name(self) -> str:
        plane = "test" if self.environment == "test" else "prod"
        purpose = "contacts" if self.contacts else "squad-statement-source"
        return f"s3rch-{plane}-{purpose}-key-{self.operation}"


def configured_binding(*, contacts: bool = False) -> SquadBinding:
    setting = "API_KEYS_CONTACTS_TEST_DEPLOYMENT_BINDING" if contacts else "API_KEYS_SQUAD_DEPLOYMENT_BINDING"
    raw = os.environ.get(setting)
    if raw is None or not authority.enabled():
        raise HTTPException(404, "Squad deployment issuance unavailable")
    try:
        value = json.loads(raw)
        binding = SquadBinding(**{**value, "tenant": uuid.UUID(value["tenant"])}, contacts=contacts)
        if ((contacts and (binding.environment != "test" or binding.tenant != CONTACTS_TENANT))
                or binding.environment not in {"test", "production"}
                or not WORKFLOW_REF.fullmatch(binding.workflow_ref)
                or ("job_workflow_ref" in value
                    and (not contacts or not WORKFLOW_REF.fullmatch(binding.job_workflow_ref)))
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
        "aud": binding.audience,
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
    job_ref = binding.job_workflow_ref
    if job_ref is not None:
        actual_job_ref = claims.get("job_workflow_ref")
    else:
        job_ref = binding.workflow_ref
        actual_job_ref = claims.get("job_workflow_ref", job_ref)
    if actual_job_ref != job_ref:
        raise HTTPException(403, "Squad deployment identity refused")


async def reconcile(
    session: AsyncSession, binding: SquadBinding, credential: str | None,
) -> dict[str, str | None]:
    selection = authority.configured_selection({
        "tenant_id": binding.tenant, "organization_id": None, "network_id": "s3r.ch",
        "scope_kind": "network", "owner_sub": binding.subject,
    })
    await authority.authorize(selection, "mint", purpose="service", scopes=binding.scopes)
    await require_owner_open(session, binding.tenant, binding.subject)

    # Serialize even when there is no candidate row to lock yet.
    lock = int.from_bytes(hashlib.sha256(
        f"squad-statement:{binding.tenant}:{binding.name}".encode()
    ).digest()[:8], "big", signed=True)
    await session.execute(text("SELECT pg_advisory_xact_lock(:lock)"), {"lock": lock})
    result = await session.execute(select(ApiKey).where(
        ApiKey.tenant_id == binding.tenant,
        ApiKey.name == binding.name,
    ).limit(2))
    rows = list(result.scalars())
    if len(rows) > 1:
        raise HTTPException(409, "Squad credential inventory ambiguous")
    if rows:
        row = rows[0]
        if row.revoked_at is not None:
            raise HTTPException(409, "Squad credential operation retired")
        owner = await authority.key_binding(session, row)
        if (row.created_by_sub != binding.subject or row.purpose != "service"
                or tuple(row.scopes or ()) != binding.scopes or not owner
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
                 name=binding.name, scopes=list(binding.scopes), created_by_sub=binding.subject,
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

def deployment_signing_key(token: str, binding: SquadBinding):
    # The trusted TEST controller can supply the issuer's public JWKS in
    # process configuration. The request never controls the trust store.
    configured = os.environ.get("API_KEYS_SQUAD_TEST_ISSUER_JWKS")
    if binding.environment != "test" or configured is None:
        return _github_keys.get_signing_key_from_jwt(token).key
    kid = jwt.get_unverified_header(token).get("kid")
    try:
        entries = json.loads(configured)["keys"]
        matches = [key for key in entries if key.get("kid") == kid
                   and key.get("kty") == "RSA" and key.get("use") == "sig"
                   and key.get("alg", "RS256") == "RS256"]
        if not isinstance(kid, str) or not kid or len(matches) != 1:
            raise jwt.InvalidTokenError()
        return jwt.PyJWK.from_dict(matches[0], algorithm="RS256").key
    except (ValueError, TypeError, KeyError, AttributeError):
        raise HTTPException(503, "Squad issuer verification unavailable") from None


def verify_deployment_token(token: str, binding: SquadBinding) -> None:
    issuer = "https://token.actions.githubusercontent.com"
    try:
        key = deployment_signing_key(token, binding)
        claims = jwt.decode(
            token, key, algorithms=["RS256"], issuer=issuer,
            audience=binding.audience,
            options={"require": ["exp", "iat", "nbf", "iss", "aud", "sub"], "strict_aud": True},
        )
    except PyJWKClientConnectionError:
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
    return await reconcile_deployment_credential(request, candidate, authorization, session, configured_binding())


@router.put("/internal/contacts-test-credential", include_in_schema=False)
async def reconcile_contacts_credential(
    request: Request,
    candidate: SquadCandidate,
    authorization: str | None = Header(None),
    session: AsyncSession = Depends(get_db_session),
):
    return await reconcile_deployment_credential(
        request, candidate, authorization, session, configured_binding(contacts=True)
    )


async def reconcile_deployment_credential(request, candidate, authorization, session, binding):
    if request.state.tenant_id != binding.tenant:
        raise HTTPException(403, "Squad deployment tenant refused")
    if (authorization is None or len(authorization) > 16384
            or not authorization.startswith("Bearer ")):
        raise HTTPException(401, "Squad issuer token required")
    await asyncio.to_thread(verify_deployment_token, authorization[7:], binding)
    credential = candidate.credential.get_secret_value() if candidate.credential is not None else None
    if credential is not None and not re.fullmatch(r"[a-f0-9]{16}\.[A-Za-z0-9_-]{43}", credential):
        raise HTTPException(400, "Squad candidate format refused")
    result = await reconcile(session, binding, credential)
    return JSONResponse(result, headers={"Cache-Control": "no-store"})
