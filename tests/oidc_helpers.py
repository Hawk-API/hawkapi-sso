"""Test helpers: a fixed RSA key for minting / verifying OIDC id_tokens."""

from __future__ import annotations

import time
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

_KID = "test-key-1"
_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwks_for() -> dict[str, Any]:
    """Return a JWKS document containing the test public key."""
    pub = _PRIVATE_KEY.public_key()
    jwk = RSAAlgorithm.to_jwk(pub, as_dict=True)
    jwk.update({"kid": _KID, "use": "sig", "alg": "RS256"})
    return {"keys": [jwk]}


def sign_id_token(
    *,
    sub: str,
    aud: str,
    iss: str,
    nonce: str = "",
    exp_delta: int = 3600,
    extra: dict[str, Any] | None = None,
) -> str:
    """Mint an RS256-signed id_token for tests."""
    now = int(time.time())
    claims: dict[str, Any] = {
        "sub": sub,
        "aud": aud,
        "iss": iss,
        "iat": now,
        "exp": now + exp_delta,
    }
    if nonce:
        claims["nonce"] = nonce
    if extra:
        claims.update(extra)
    return jwt.encode(claims, _PRIVATE_KEY, algorithm="RS256", headers={"kid": _KID})
