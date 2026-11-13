from types import SimpleNamespace
from unittest.mock import AsyncMock
import uuid

import pytest
from fastapi import HTTPException

from api_keys_service import routes
from api_keys_service.internal_auth import accepted_tokens, caller_token_matches

CURRENT='a'*48
PREVIOUS='b'*48


def configured(previous=PREVIOUS):
    return SimpleNamespace(usable_api_keys_internal_token=lambda:CURRENT,
                           api_keys_internal_token_previous=previous)


@pytest.mark.parametrize('presented,allowed',[(CURRENT,True),(PREVIOUS,True),('wrong',False),('',False),(None,False)])
def test_overlap_only_accepts_declared_credentials(presented,allowed):
    assert caller_token_matches(presented,configured()) is allowed


def test_previous_cannot_replace_missing_current():
    settings=configured();settings.usable_api_keys_internal_token=lambda:None
    assert not caller_token_matches(PREVIOUS,settings)


@pytest.mark.parametrize('previous',['short','dev-'+'x'*40,'laptop-'+'x'*40,CURRENT])
def test_bad_overlap_refused_without_value_in_exception(previous):
    with pytest.raises(ValueError) as error:accepted_tokens(configured(previous))
    assert previous not in str(error.value)


def test_clearing_overlap_refuses_old_token():
    assert caller_token_matches(CURRENT,configured(''))
    assert not caller_token_matches(PREVIOUS,configured(''))


def test_older_settings_package_accepts_explicit_overlap(monkeypatch):
    monkeypatch.setenv('API_KEYS_INTERNAL_TOKEN_PREVIOUS',PREVIOUS)
    settings=SimpleNamespace(usable_api_keys_internal_token=lambda:CURRENT)
    assert accepted_tokens(settings)==(CURRENT,PREVIOUS)


@pytest.mark.parametrize('presented',[CURRENT,PREVIOUS])
async def test_validate_and_touch_accept_overlap_before_owner_lookup(monkeypatch,presented):
    monkeypatch.setattr(routes,'settings',configured())
    session=SimpleNamespace(execute=AsyncMock(return_value=SimpleNamespace(scalar_one_or_none=lambda:None)),flush=AsyncMock())
    monkeypatch.setattr(routes.authority,'enabled',lambda:False)
    result=await routes.internal_validate(routes.InternalValidateRequest(api_key='malformed',tenant_id=uuid.uuid4()),presented,session)
    assert not result.valid
    session.execute.assert_not_awaited()
    await routes.internal_touch(routes.InternalTouchRequest(key_id=uuid.uuid4()),presented,session,None)
    session.execute.assert_awaited_once()


@pytest.mark.parametrize('endpoint',['validate','touch'])
async def test_retired_token_rejected_before_database(monkeypatch,endpoint):
    monkeypatch.setattr(routes,'settings',configured(''))
    session=SimpleNamespace(execute=AsyncMock())
    with pytest.raises(HTTPException) as error:
        if endpoint=='validate':
            await routes.internal_validate(routes.InternalValidateRequest(api_key='malformed',tenant_id=uuid.uuid4()),PREVIOUS,session)
        else:
            await routes.internal_touch(routes.InternalTouchRequest(key_id=uuid.uuid4()),PREVIOUS,session,None)
    assert error.value.status_code==401
    session.execute.assert_not_awaited()
