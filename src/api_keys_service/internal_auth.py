"""Internal caller verification during independent credential rotation."""
import os

from api.common.internal_token import internal_token_matches


def accepted_tokens(settings):
    current = settings.usable_api_keys_internal_token()
    if not current:
        return ()
    # Older compatible configuration packages expose only the current helper.
    # Read the new setting directly in that case; do not require matching peers.
    previous = getattr(settings, 'api_keys_internal_token_previous',
                       os.environ.get('API_KEYS_INTERNAL_TOKEN_PREVIOUS', ''))
    previous = (previous or '').strip()
    if previous and (len(previous) < 32 or previous.lower().startswith(('dev-', 'laptop-', 'replace-with'))
                     or previous == current):
        raise ValueError('API_KEYS_INTERNAL_TOKEN_PREVIOUS must be a distinct private credential')
    return (current, previous) if previous else (current,)


def caller_token_matches(presented, settings):
    return any(internal_token_matches(presented, expected) for expected in accepted_tokens(settings))
