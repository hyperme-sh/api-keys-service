import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from fastapi import HTTPException
import pytest

from api_keys_service import squad_issuance as squad


def binding(environment="test"):
    return squad.SquadBinding(
        environment, uuid.UUID(int=1), str(uuid.UUID(int=2)),
        "FyberLabs/infra/.github/workflows/squad-credential.yml@refs/heads/main",
        "123", "456", "a" * 32,
    )


@pytest.fixture
def claims():
    return {
        "aud": "spanopticon:squad-statement-issuance:test",
        "repository": "FyberLabs/infra",
        "repository_id": "123",
        "repository_owner_id": "456",
        "environment": "test",
        "sub": "repo:FyberLabs/infra:environment:test",
        "ref": "refs/heads/main",
        "workflow_ref": binding().workflow_ref,
    }


@pytest.mark.parametrize("claim,value", [
    ("repository_id", "124"), ("repository_owner_id", "457"),
    ("ref", "refs/pull/1/merge"), ("environment", "production"),
    ("job_workflow_ref", "another-workflow"), ("workflow_ref", "another-workflow"),
    ("aud", "spanopticon:squad-statement-issuance:production"),
])
def test_refuses_wrong_workload_binding(claims, claim, value):
    squad.require_deployment_claims(claims, binding())
    with pytest.raises(HTTPException, match="deployment identity refused"):
        squad.require_deployment_claims({**claims, claim: value}, binding())


async def test_reuses_only_the_existing_matching_credential(monkeypatch):
    configured = binding()
    row = SimpleNamespace(
        id=uuid.UUID(int=3), created_by_sub=configured.subject,
        purpose="service", scopes=squad.SCOPES, revoked_at=None, key_prefix="a" * 16, secret_hash="fixture",
    )
    db = SimpleNamespace(execute=AsyncMock(return_value=Mock(scalars=lambda: [row])), add=Mock())
    authorize = AsyncMock()
    monkeypatch.setattr(squad.authority, "configured_selection", Mock())
    monkeypatch.setattr(squad.authority, "authorize", authorize)
    monkeypatch.setattr(squad, "require_owner_open", AsyncMock())
    monkeypatch.setattr(squad.authority, "key_binding", AsyncMock(return_value={
        "network_id": "s3r.ch", "scope_kind": "network", "organization_id": None,
    }))
    verify = Mock(return_value=True)
    monkeypatch.setattr(squad, "verify_secret", verify)
    credential = "a" * 16 + "." + "b" * 43
    assert await squad.reconcile(db, configured, credential) == {
        "state": "active", "key_id": str(row.id),
    }
    assert authorize.await_args.kwargs == {"purpose": "service", "scopes": squad.SCOPES}
    verify.return_value = False
    with pytest.raises(HTTPException, match="credential value differs"):
        await squad.reconcile(db, configured, credential)
    row.revoked_at = object()
    with pytest.raises(HTTPException, match="operation retired"):
        await squad.reconcile(db, configured, credential)
    db.add.assert_not_called()
