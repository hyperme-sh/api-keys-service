from api_keys_service.crypto import hash_secret, verify_secret


def test_bcrypt_roundtrip() -> None:
    h = hash_secret("secret-part")
    assert verify_secret("secret-part", h)
    assert not verify_secret("wrong", h)
