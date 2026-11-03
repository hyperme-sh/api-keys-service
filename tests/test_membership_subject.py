
from types import SimpleNamespace
from unittest.mock import AsyncMock
import uuid
import pytest
from auth_service.schemas import AuthMeResponse
from api_keys_service.allowlist import _membership_names

@pytest.mark.asyncio
@pytest.mark.parametrize('subject,active', [('other', True), (None, True), ('caller', False)])
async def test_conflicting_unbound_or_inactive_member_has_no_grants(subject, active):
    row = SimpleNamespace(keycloak_sub=subject, is_active=active)
    session = SimpleNamespace(execute=AsyncMock(return_value=SimpleNamespace(scalar_one_or_none=lambda: row)))
    assert await _membership_names(session, uuid.uuid4(), AuthMeResponse(sub='caller', email='reassigned@example.test')) == ([], [])
    assert session.execute.await_count == 1

@pytest.mark.asyncio
async def test_membership_lookup_uses_subject_even_after_email_changes():
    tid = uuid.uuid4()
    row = SimpleNamespace(id=uuid.uuid4(), keycloak_sub='caller', is_active=True, role_id=uuid.uuid4())
    results = [SimpleNamespace(scalar_one_or_none=lambda: row),
               SimpleNamespace(scalar_one_or_none=lambda: SimpleNamespace(name='admin')),
               SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: ['renter']))]
    session = SimpleNamespace(execute=AsyncMock(side_effect=results))
    assert await _membership_names(session, tid, AuthMeResponse(sub='caller', email='new@example.test')) == (['admin'], ['renter'])
    query = session.execute.await_args_list[0].args[0].compile()
    assert 'caller' in query.params.values()
    assert tid in query.params.values()
    assert 'new@example.test' not in query.params.values()

@pytest.mark.asyncio
async def test_email_alone_cannot_resolve_membership():
    session = SimpleNamespace(execute=AsyncMock())
    assert await _membership_names(session, uuid.uuid4(), AuthMeResponse(sub='', email='admin@example.test')) == ([], [])
    session.execute.assert_not_awaited()
