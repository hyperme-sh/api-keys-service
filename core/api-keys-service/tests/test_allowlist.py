import uuid

import pytest
from fastapi import HTTPException

from api.common.portal_controls import evaluate_portal_controls
from api_keys_service.allowlist import MINT_REFUSED, mint_allowed


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
        / "hypermesh-router"
        / "src"
        / "hypermesh_router_service"
        / "chat.py"
    )
    source = chat.read_text(encoding="utf-8")
    assert "api_keys" not in source
    assert "portal_controls" not in source
    assert "Keycloak" not in source


def test_refuse_message_is_portal_not_chat():
    assert "org admin" in MINT_REFUSED
    assert "renter" in MINT_REFUSED


@pytest.mark.asyncio
async def test_create_route_checks_allowlist(monkeypatch):
    from api_keys_service import routes as r

    async def deny(*_a, **_k):
        return False

    monkeypatch.setattr(r, "actor_can_mint_keys", deny)

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


def test_evaluate_matches_mint_allowed():
    assert evaluate_portal_controls(["admin"], []).can_mint_keys is True
    assert evaluate_portal_controls(["guest"], []).can_mint_keys is False
