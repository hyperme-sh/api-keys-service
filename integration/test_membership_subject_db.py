"""Subject-bound membership authorization against a disposable owning database."""
import uuid

import pytest
from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from starlette.requests import Request

from auth_service.schemas import AuthMeResponse
from api_keys_service.allowlist import actor_controls
from api_keys_service.routes import create_api_key
from api_keys_service.schemas import ApiKeyCreateRequest
from controlplane_db.models import ApiKey, Group, Role, Tenant, User, UserGroupMembership


@pytest.mark.parametrize('case', ['reassigned', 'unbound', 'inactive', 'missing', 'changed_email', 'foreign_group'])
async def test_database_membership_controls_key_authority(lifecycle_database, case):
    engine = create_async_engine(lifecycle_database)
    tenant, other = uuid.uuid4(), uuid.uuid4()
    subject = 'owner-' + uuid.uuid4().hex
    email = subject + '@example.com'
    try:
        async with async_sessionmaker(engine, expire_on_commit=False)() as session:
            session.add_all([Tenant(id=tid, name=str(tid), is_active=True) for tid in (tenant, other)])
            await session.flush()
            role = Role(id=uuid.uuid4(), tenant_id=tenant,
                        name='user' if case == 'foreign_group' else 'admin', permissions=[])
            foreign_role = Role(id=uuid.uuid4(), tenant_id=other, name='user', permissions=[])
            session.add_all([role, foreign_role])
            await session.flush()
            member = User(id=uuid.uuid4(), tenant_id=tenant, role_id=role.id, email=email,
                keycloak_sub=None if case == 'unbound' else subject, is_active=True,
                first_name='Membership', last_name='Test', gender='unspecified')
            group = Group(id=uuid.uuid4(), tenant_id=other if case == 'foreign_group' else tenant,
                          role_id=foreign_role.id if case == 'foreign_group' else role.id, name='billing')
            session.add_all([member, group])
            await session.flush()
            session.add(UserGroupMembership(id=uuid.uuid4(), tenant_id=tenant,
                                            user_id=member.id, group_id=group.id))
            await session.flush()
            if case == 'inactive':
                # Admission refuses a new membership on an already inactive
                # profile. Deactivate after the row exists.
                member.is_active = False
                await session.flush()
            actor = AuthMeResponse(sub='' if case == 'missing' else 'replacement' if case == 'reassigned' else subject,
                                   email='changed@example.com' if case == 'changed_email' else email)
            controls = await actor_controls(session, tenant, actor)
            assert controls.can_mint_keys is (case == 'changed_email')
            assert controls.can_use_ir_door is (case == 'changed_email')
            if case != 'changed_email':
                request = Request({'type': 'http', 'headers': [], 'state': {'tenant_id': tenant}})
                with pytest.raises(HTTPException) as error:
                    await create_api_key(request, actor, ApiKeyCreateRequest(name='refused'), tenant, session, {})
                assert error.value.status_code == 403
                assert await session.scalar(select(func.count()).select_from(ApiKey).where(ApiKey.tenant_id == tenant)) == 0
    finally:
        await engine.dispose()
