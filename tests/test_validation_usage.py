from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock
import uuid

import pytest
from jwt import InvalidTokenError

from api_keys_service import routes


@pytest.mark.parametrize('failure', [None, 'missing', 'revoked', 'tenant', 'secret', 'authority', 'closed'])
async def test_validation_records_only_authorized_usage(monkeypatch, failure):
    tenant = uuid.uuid4()
    previous = datetime(2020, 1, 1, tzinfo=UTC)
    row = SimpleNamespace(id=uuid.uuid4(), tenant_id=tenant, secret_hash='fixture-hash',
                          revoked_at=None, created_by_sub='fixture-owner',
                          purpose='service', scopes=['oracles:attest'], last_used_at=previous)
    if failure == 'revoked':
        row.revoked_at = previous
    if failure == 'tenant':
        row.tenant_id = uuid.uuid4()
    session = SimpleNamespace(
        execute=AsyncMock(return_value=SimpleNamespace(scalar_one_or_none=lambda: None if failure == 'missing' else row)),
        flush=AsyncMock(),
    )
    monkeypatch.setattr(type(routes.settings), 'usable_api_keys_internal_token', lambda self: 'fixture-internal')
    monkeypatch.setattr(routes, 'set_current_tenant_id_guc', AsyncMock())
    monkeypatch.setattr(routes, 'verify_secret', lambda secret, hashed: failure != 'secret')
    monkeypatch.setattr(routes.authority, 'enabled', lambda: True)
    monkeypatch.setattr(routes.authority, 'key_use', AsyncMock(return_value=failure != 'authority'))

    def account_check(claims):
        if failure == 'closed':
            raise InvalidTokenError('fixture account closed')

    monkeypatch.setattr('controlplane_identity.account_lifecycle.require_open_account', account_check)
    result = await routes.internal_validate(
        routes.InternalValidateRequest(api_key='fixture.secret', tenant_id=tenant),
        'fixture-internal', session,
    )
    assert result.valid is (failure is None)
    if failure:
        assert row.last_used_at == previous
        session.flush.assert_not_awaited()
    else:
        assert row.last_used_at > previous
        assert result.key_id == row.id
        session.flush.assert_awaited_once()
