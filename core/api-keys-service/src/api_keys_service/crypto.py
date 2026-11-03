from __future__ import annotations

import bcrypt


def hash_secret(plaintext: str) -> str:
    return bcrypt.hashpw(plaintext.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def verify_secret(plaintext: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(
            plaintext.encode("utf-8"),
            hashed.encode("ascii"),
        )
    except ValueError:
        return False
