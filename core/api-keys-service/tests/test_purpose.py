import pytest
from pydantic import ValidationError

from api_keys_service.schemas import ApiKeyCreateRequest


def test_key_mint_defaults_purpose_to_renter():
    body = ApiKeyCreateRequest(name="agent")
    assert body.purpose == "renter"


def test_key_mint_accepts_service_and_rejects_ir():
    assert ApiKeyCreateRequest(purpose="service").purpose == "service"
    assert ApiKeyCreateRequest(purpose="named service account").purpose == "service"
    with pytest.raises(ValidationError):
        ApiKeyCreateRequest(purpose="ir")
    with pytest.raises(ValidationError):
        ApiKeyCreateRequest(purpose="workspace")
