"""OIDC ID-token verification — JWKS-backed signature / claim validation.

Pure OAuth2 providers (GitHub, Facebook, Discord) never touch this module; it is
gated behind :attr:`OAuthProvider.is_oidc` / a populated ``jwks_url``. The JWK set
is fetched by the caller through the provider's own (redirect-disabled) httpx
client so it can be mocked in tests and benefits from the same SSRF hardening.
"""

from __future__ import annotations

import time
from typing import Any

import jwt
from jwt import PyJWKSet


class OIDCError(Exception):
    """Raised when an OIDC ``id_token`` fails signature or claim validation."""


def verify_id_token(
    id_token: str,
    *,
    jwks: dict[str, Any],
    issuer: str,
    audience: str,
    nonce: str,
    leeway: int = 60,
) -> dict[str, Any]:
    """Verify an OIDC ``id_token`` against ``jwks`` and return its validated claims.

    Validates the JWS signature, plus ``iss`` (when non-empty), ``aud``, ``exp``
    and ``nonce``. Raises :class:`OIDCError` on any failure.
    """
    if not id_token:
        raise OIDCError("id_token missing from token response")
    # An empty issuer (e.g. multi-tenant Microsoft "common") means ``iss`` is
    # dynamic — skip strict matching but still require the claim to be present.
    verify_iss = bool(issuer)
    try:
        key_set = PyJWKSet.from_dict(jwks)
        header = jwt.get_unverified_header(id_token)
        kid = header.get("kid")
        signing_key = None
        for key in key_set.keys:
            if kid is None or key.key_id == kid:
                signing_key = key
                break
        if signing_key is None:
            raise OIDCError("no matching JWKS key for id_token")
        claims: dict[str, Any] = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            audience=audience,
            issuer=issuer or None,
            leeway=leeway,
            options={
                "require": ["exp", "iat", "iss", "aud", "sub"],
                "verify_iss": verify_iss,
            },
        )
    except jwt.PyJWTError as exc:
        raise OIDCError(f"id_token validation failed: {exc}") from exc
    exp = int(claims.get("exp", 0) or 0)
    if exp and exp + leeway < int(time.time()):
        raise OIDCError("id_token expired")
    if nonce and claims.get("nonce") != nonce:
        raise OIDCError("id_token nonce mismatch")
    if "sub" not in claims:
        raise OIDCError("id_token missing sub")
    return claims


__all__ = ["OIDCError", "verify_id_token"]
