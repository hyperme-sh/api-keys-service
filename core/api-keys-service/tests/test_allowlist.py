import uuid

import pytest
from fastapi import HTTPException

from api.common.portal_controls import evaluate_portal_controls
from api_keys_service.allowlist import (
    IR_MINT_REFUSED,
    MINT_REFUSED,
    ir_purpose_mint_allowed,
    is_smoke_session,
    mint_allowed,
    smoke_may_mint,
    smoke_owns_key,
)


def test_mint_allowed_for_admin_renter_and_billing():
    assert mint_allowed(["admin"], []) is True
    assert mint_allowed(["user"], ["renter"]) is True
    assert mint_allowed([], ["/billing"]) is True
    assert mint_allowed(["billing_manager"], []) is True


def test_mint_refused_for_host_and_guest():
    assert mint_allowed(["host"], []) is False
    assert mint_allowed(["guest"], []) is False
    assert mint_allowed([], ["workspace"]) is False


def test_chat_path_does_not_import_allowlist_from_router():
    # Completions stay on the router. This module is portal / api-keys only.
    from pathlib import Path

    chat = (
        Path(__file__).resolve().parents[3]
        / "products"
        / "hypermesh-gateway"
        / "src"
        / "hypermesh_gateway_service"
        / "chat.py"
    )
    source = chat.read_text(encoding="utf-8")
    assert "api_keys" not in source
    assert "portal_controls" not in source
    assert "Keycloak" not in source
    routes = (
        Path(__file__).resolve().parents[3]
        / "products"
        / "hypermesh-gateway"
        / "src"
        / "hypermesh_gateway_service"
        / "routes.py"
    )
    route_src = routes.read_text(encoding="utf-8")
    assert "api_keys_service" not in route_src
    assert "actor_can_mint_keys" not in route_src


def test_refuse_message_is_portal_not_chat():
    assert "org admin" in MINT_REFUSED
    assert "renter" in MINT_REFUSED
    assert "ir group" in IR_MINT_REFUSED


def test_ir_purpose_mint_is_separate_from_renter_mint():
    assert ir_purpose_mint_allowed(["admin"], []) is True
    assert ir_purpose_mint_allowed(["user"], ["ir"]) is True
    assert ir_purpose_mint_allowed(["user"], ["renter"]) is False
    assert ir_purpose_mint_allowed(["user"], ["ir_export"]) is False
    assert ir_purpose_mint_allowed(["guest"], []) is False
    assert mint_allowed(["user"], ["ir"]) is False
    assert mint_allowed(["user"], ["renter"]) is True


@pytest.mark.asyncio
async def test_create_route_checks_allowlist(monkeypatch):
    from api.common.portal_controls import evaluate_portal_controls
    from api_keys_service import routes as r

    async def guest(*_a, **_k):
        return evaluate_portal_controls(["guest"], [])

    monkeypatch.setattr(r, "actor_controls", guest)

    class _Req:
        state = type("S", (), {"tenant_id": uuid.uuid4()})()

    class _User:
        roles = ["guest"]
        groups: list[str] = []
        email = "g@example.com"

    with pytest.raises(HTTPException) as exc:
        await r.create_api_key(
            request=_Req(),  # type: ignore[arg-type]
            user=_User(),  # type: ignore[arg-type]
            body=r.ApiKeyCreateRequest(name="x"),
            _=uuid.uuid4(),
            session=None,  # type: ignore[arg-type]
        )
    assert exc.value.status_code == 403
    assert exc.value.detail == MINT_REFUSED


@pytest.mark.asyncio
async def test_create_route_refuses_ir_purpose_without_ir_grant(monkeypatch):
    from api.common.portal_controls import evaluate_portal_controls
    from api_keys_service import routes as r

    async def renter(*_a, **_k):
        return evaluate_portal_controls(["user"], ["renter"])

    monkeypatch.setattr(r, "actor_controls", renter)

    class _Req:
        state = type("S", (), {"tenant_id": uuid.uuid4()})()

    class _User:
        roles = ["user"]
        groups = ["renter"]
        email = "r@example.com"

    with pytest.raises(HTTPException) as exc:
        await r.create_api_key(
            request=_Req(),  # type: ignore[arg-type]
            user=_User(),  # type: ignore[arg-type]
            body=r.ApiKeyCreateRequest(name="ir-bot", purpose="ir"),
            _=uuid.uuid4(),
            session=None,  # type: ignore[arg-type]
        )
    assert exc.value.status_code == 403
    assert exc.value.detail == IR_MINT_REFUSED


def test_smoke_session_mints_only_its_own_renter_key():
    smoke = {"hypermesh_smoke": True}
    assert is_smoke_session(smoke) is True
    assert is_smoke_session({"hypermesh_smoke": False}) is False
    assert smoke_may_mint(smoke, "renter", []) is True
    assert smoke_may_mint(smoke, "ir", []) is False
    assert smoke_may_mint(smoke, "service", []) is False
    assert smoke_may_mint(smoke, "renter", ["admin"]) is False
    assert smoke_may_mint(None, "ir", ["admin"]) is True
    assert smoke_owns_key(smoke, "hypermesh-smoke@test.hyperme.sh", "Hypermesh-Smoke@test.hyperme.sh")
    assert smoke_owns_key(smoke, "other@test.hyperme.sh", "hypermesh-smoke@test.hyperme.sh") is False
    assert smoke_owns_key(None, "other@test.hyperme.sh", "hypermesh-smoke@test.hyperme.sh") is True


@pytest.mark.asyncio
async def test_create_route_refuses_smoke_session_ir_purpose(monkeypatch):
    from api.common.portal_controls import evaluate_portal_controls
    from api_keys_service import routes as r

    async def renter(*_a, **_k):
        return evaluate_portal_controls(["user"], ["renter"])

    monkeypatch.setattr(r, "actor_controls", renter)

    class _Req:
        state = type("S", (), {"tenant_id": uuid.uuid4()})()

    class _User:
        roles = ["user"]
        groups = ["renter"]
        email = "hypermesh-smoke@test.hyperme.sh"

    with pytest.raises(HTTPException) as exc:
        await r.create_api_key(
            request=_Req(),  # type: ignore[arg-type]
            user=_User(),  # type: ignore[arg-type]
            body=r.ApiKeyCreateRequest(name="ir-bot", purpose="ir"),
            _=uuid.uuid4(),
            session=None,  # type: ignore[arg-type]
            claims={"hypermesh_smoke": True},
        )
    assert exc.value.status_code == 403
    assert exc.value.detail == "smoke session may only mint a renter key"


def test_evaluate_matches_mint_allowed():
    assert evaluate_portal_controls(["admin"], []).can_mint_keys is True
    assert evaluate_portal_controls(["guest"], []).can_mint_keys is False


def test_configured_smoke_marker_keeps_key_restrictions(monkeypatch):
    from api.core.config import settings
    monkeypatch.setattr(settings, "smoke_session_claim", "example_smoke")
    claims = {"example_smoke": True, "smoke_session": True}
    assert is_smoke_session(claims)
    assert smoke_may_mint(claims, "renter", [])
    assert not smoke_may_mint(claims, "host", [])
    assert not smoke_may_mint(claims, "renter", ["admin"])
    assert not smoke_owns_key(claims, "another@example.test", "smoke@example.test")


@pytest.mark.parametrize("consumer_marker", ["hypermesh_smoke", "other_smoke"])
@pytest.mark.parametrize("legacy_only", [False, True])
def test_smoke_classification_survives_independent_service_rollout(monkeypatch, consumer_marker, legacy_only):
    from api.core.config import settings
    from controlplane_identity.security.tenant_session_jwt import mint_tenant_session_jwt, try_decode_tenant_session_jwt
    monkeypatch.setattr(settings, "api_key_exchange_jwt_secret", "rollout-test-secret-at-least-32-characters")
    monkeypatch.setattr(settings, "smoke_session_claim", "producer_smoke")
    token = mint_tenant_session_jwt(claims={"sub": "smoke-user", "email": "smoke@example.test",
        "smoke_session": True, "producer_smoke": True}, tenant_id=uuid.uuid4(), extra_roles=["renter"])
    claims = try_decode_tenant_session_jwt(token)
    assert claims is not None
    # Existing API-key releases classify this marker without configuration.
    assert claims["hypermesh_smoke"] is True
    if legacy_only:
        # Sessions minted before this extraction remain restricted too.
        claims.pop("smoke_session")
        claims.pop("producer_smoke")
        import jwt
        token = jwt.encode(claims, settings.usable_api_key_exchange_secret(), algorithm="HS256")
        claims = try_decode_tenant_session_jwt(token)
        assert claims is not None
    monkeypatch.setattr(settings, "smoke_session_claim", consumer_marker)
    assert is_smoke_session(claims)
    assert not smoke_may_mint(claims, "ir", [])
    assert not smoke_may_mint(claims, "renter", ["admin"])
    assert not smoke_owns_key(claims, "other@example.test", "smoke@example.test")


def test_configured_metadata_is_not_authorization(monkeypatch):
    from api.core.config import settings
    monkeypatch.setattr(settings, "smoke_session_claim", "example_smoke")
    assert not is_smoke_session({"example_smoke": True})
    assert not is_smoke_session({"smoke_session": "true", "hypermesh_smoke": False})


@pytest.mark.asyncio
@pytest.mark.parametrize("claims", [{"smoke_session": True, "producer_smoke": True}, {"hypermesh_smoke": True}])
async def test_mismatched_marker_cannot_list_or_revoke_another_users_key(monkeypatch, claims):
    from datetime import UTC, datetime
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from api.core.config import settings
    from api_keys_service import routes
    monkeypatch.setattr(settings, "smoke_session_claim", "different_consumer_marker")
    tenant_id = uuid.uuid4()
    request = SimpleNamespace(state=SimpleNamespace(tenant_id=tenant_id))
    user = SimpleNamespace(email="smoke@example.test")
    def row(email):
        return SimpleNamespace(id=uuid.uuid4(), tenant_id=tenant_id, created_by_sub=email,
            key_prefix="pk_test", name="key", scopes=[], created_at=datetime.now(UTC), revoked_at=None)
    own, other = row(user.email), row("other@example.test")
    result = SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: [own, other]),
                             scalar_one_or_none=lambda: other)
    session = SimpleNamespace(execute=AsyncMock(return_value=result), flush=AsyncMock())
    monkeypatch.setattr(routes, "_mapped_lease", AsyncMock(return_value=None))
    monkeypatch.setattr(routes, "actor_can_mint_keys", AsyncMock(return_value=True))
    listed = await routes.list_api_keys(request, user, tenant_id, session, claims)
    assert [key.id for key in listed] == [own.id]
    with pytest.raises(HTTPException) as exc:
        await routes.revoke_api_key(other.id, request, user, tenant_id, session, claims)
    assert exc.value.status_code == 404
    assert other.revoked_at is None
    session.flush.assert_not_awaited()


def test_smoke_owns_key_by_immutable_subject_after_email_change():
    claims = {"smoke_session": True, "sub": "stable-person"}
    assert smoke_owns_key(claims, "stable-person", "new@example.com")
    assert not smoke_owns_key(claims, "another-person", "new@example.com")
