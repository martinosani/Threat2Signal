"""Authentication and authorization for the API."""

import logging
from datetime import datetime, timezone, timedelta

import jwt
from passlib.hash import bcrypt

logger = logging.getLogger(__name__)


def hash_password(plain: str) -> str:
    """Return a bcrypt hash of the plaintext password."""
    return bcrypt.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Check a plaintext password against a bcrypt hash."""
    return bcrypt.verify(plain, hashed)


def find_user(username: str, users: list[dict]) -> dict | None:
    """Find a user dict by username, or None if not found."""
    for user in users:
        if user.get("username") == username:
            return user
    return None


def create_token(username: str, role: str, secret: str, expiry_hours: int) -> str:
    """Build and sign a JWT with sub, role, and exp claims."""
    payload = {
        "sub": username,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=expiry_hours),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def validate_token(token: str, secret: str) -> dict:
    """Decode and verify a JWT.

    Raises jwt.ExpiredSignatureError or jwt.InvalidTokenError on failure;
    the caller is responsible for handling those.
    """
    return jwt.decode(token, secret, algorithms=["HS256"])
