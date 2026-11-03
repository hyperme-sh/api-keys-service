import pytest
from pydantic import ValidationError

from api_keys_service.schemas import ApiKeyCreateRequest


def test_key_mint_defaults_purpose_to_renter():
    body = ApiKeyCreateRequest(name="agent")
    assert body.purpose == "renter"


def test_key_mint_accepts_service_and_ir_and_rejects_workspace():
    assert ApiKeyCreateRequest(purpose="service").purpose == "service"
    assert ApiKeyCreateRequest(purpose="named service account").purpose == "service"
    assert ApiKeyCreateRequest(purpose="ir").purpose == "ir"
    with pytest.raises(ValidationError):
        ApiKeyCreateRequest(purpose="workspace")
