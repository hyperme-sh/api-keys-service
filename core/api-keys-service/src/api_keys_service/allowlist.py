"""API key mint/revoke allowlist for portal slice 2.

Belongs on this service, not on the chat hot path. Completions stay
format-only plus a paid ticket. They do not hop here.
"""

from __future__ import annotations

from controlplane_identity.security.tenant_session_jwt import is_smoke_session

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.common.portal_controls import PortalControls, evaluate_portal_controls
from auth_service.schemas import AuthMeResponse
from controlplane_db.models import Group, Role, User, UserGroupMembership

MINT_REFUSED = (
    "API key mint/revoke is limited to org admin or the billing or renter group"
)
IR_MINT_REFUSED = (
    "purpose ir API keys are limited to org admin or the ir group"
)


def mint_allowed(
    roles: list[str] | None,
    groups: list[str] | None,
) -> bool:
    return evaluate_portal_controls(roles, groups).can_mint_keys


def smoke_may_mint(claims: dict | None, purpose: str, scopes: list | None) -> bool:
    """Smoke sessions mint one renter key. Other sessions are not limited here."""

    if not is_smoke_session(claims):
        return True
    return purpose == "renter" and not scopes


def smoke_owns_key(
    claims: dict | None,
    created_by_sub: str | None,
    actor_email: str | None,
) -> bool:
    """Smoke sessions touch only keys they created. Other sessions are not limited here."""

    if not is_smoke_session(claims):
        return True
    # New keys bind the immutable subject; retain email matching for old smoke keys.
    subject = str((claims or {}).get("sub") or "")
    if subject and created_by_sub == subject:
        return True
    actor = (actor_email or "").strip().lower()
    owner = (created_by_sub or "").strip().lower()
    return bool(actor) and actor == owner


def ir_purpose_mint_allowed(
    roles: list[str] | None,
    groups: list[str] | None,
) -> bool:
    return evaluate_portal_controls(roles, groups).can_use_ir_door


async def _membership_names(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    user: AuthMeResponse,
) -> tuple[list[str], list[str]]:
    roles: list[str] = []
    groups: list[str] = []
    row: User | None = None
    if user.email:
        q = await session.execute(
            select(User).where(
                User.tenant_id == tenant_id,
                User.email == user.email.lower(),
                User.deleted_at.is_(None),
            )
        )
        row = q.scalar_one_or_none()
    if row is None and user.sub:
        q = await session.execute(
            select(User).where(
                User.tenant_id == tenant_id,
                User.keycloak_sub == user.sub,
                User.deleted_at.is_(None),
            )
        )
        row = q.scalar_one_or_none()
    if row is None:
        return roles, groups
    if row.role_id is not None:
        rq = await session.execute(
            select(Role).where(Role.id == row.role_id, Role.tenant_id == tenant_id)
        )
        role = rq.scalar_one_or_none()
        if role is not None:
            roles.append(role.name)
    gq = await session.execute(
        select(Group.name)
        .join(UserGroupMembership, UserGroupMembership.group_id == Group.id)
        .where(
            UserGroupMembership.tenant_id == tenant_id,
            UserGroupMembership.user_id == row.id,
        )
    )
    groups.extend(str(name) for name in gq.scalars().all())
    return roles, groups


async def actor_controls(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    user: AuthMeResponse,
) -> PortalControls:
    roles = list(user.roles)
    groups = list(user.groups)
    try:
        extra_roles, extra_groups = await _membership_names(session, tenant_id, user)
    except Exception:
        extra_roles, extra_groups = [], []
    roles.extend(extra_roles)
    groups.extend(extra_groups)
    return evaluate_portal_controls(roles, groups)


async def actor_can_mint_keys(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    user: AuthMeResponse,
) -> bool:
    return (await actor_controls(session, tenant_id, user)).can_mint_keys


async def actor_can_use_ir_door(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    user: AuthMeResponse,
) -> bool:
    return (await actor_controls(session, tenant_id, user)).can_use_ir_door
