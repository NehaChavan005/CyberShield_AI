from datetime import datetime, timezone
import hashlib
import hmac
import secrets

import jwt

from auth.config import JWT_ALGORITHM, JWT_SECRET_KEY, token_expiry


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    derived_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return f"{salt}${derived_key.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    salt, expected_hash = hashed_password.split("$", maxsplit=1)
    derived_key = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return hmac.compare_digest(derived_key.hex(), expected_hash)


def create_access_token(subject: str) -> str:
    expires_at = datetime.now(timezone.utc) + token_expiry()
    payload = {"sub": subject, "exp": expires_at}
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
