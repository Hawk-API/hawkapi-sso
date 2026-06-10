"""HMAC-signed opaque state token used to defeat CSRF on the OAuth callback."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass


@dataclass(slots=True)
class StatePayload:
    nonce: str
    provider: str
    redirect_uri: str
    next_url: str = "/"
    # NOTE: ``code_verifier`` is intentionally NOT serialized into the signed
    # state token — that token travels to the authorization server as the
    # ``state=`` query param, where the PKCE verifier would leak (provider logs,
    # Referer) and defeat PKCE. It is carried instead in a separate server-side
    # cookie (see ``sign_pkce`` / the routes module) that is never sent upstream.
    code_verifier: str = ""
    iat: int = 0


_STATE_TTL_SECONDS = 600  # 10 minutes


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _ub64(data: str) -> bytes:
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data = data + ("=" * padding)
    return base64.urlsafe_b64decode(data.encode("ascii"))


def sign_state(payload: StatePayload, *, secret: str, include_verifier: bool = False) -> str:
    """Sign a state payload. Output is ``base64(json).base64(hmac)``.

    ``include_verifier`` MUST stay ``False`` for the token placed in the ``state=``
    authorization URL param — the PKCE ``code_verifier`` would otherwise leak to the
    provider. It is set ``True`` only for the value stored in the state COOKIE, which
    is never transmitted to the authorization server.
    """
    if not secret:
        raise ValueError("state secret is required")
    body = {
        "nonce": payload.nonce,
        "provider": payload.provider,
        "redirect_uri": payload.redirect_uri,
        "next_url": payload.next_url,
        "iat": payload.iat or int(time.time()),
    }
    if include_verifier:
        body["code_verifier"] = payload.code_verifier
    body_bytes = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).digest()
    return f"{_b64(body_bytes)}.{_b64(sig)}"


def verify_state(token: str, *, secret: str, ttl: int = _STATE_TTL_SECONDS) -> StatePayload:
    """Inverse of :func:`sign_state`. Raises ValueError on tampering / expiry."""
    if not secret:
        raise ValueError("state secret is required")
    try:
        body_b64, sig_b64 = token.split(".", 1)
        body_bytes = _ub64(body_b64)
        sig = _ub64(sig_b64)
    except (ValueError, TypeError) as exc:
        raise ValueError("malformed state token") from exc
    expected = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, sig):
        raise ValueError("state signature mismatch")
    try:
        body = json.loads(body_bytes)
    except ValueError as exc:
        raise ValueError("state payload is not JSON") from exc
    if not isinstance(body, dict):
        raise ValueError("state payload is not an object")
    iat = int(body.get("iat", 0) or 0)
    if iat <= 0:
        raise ValueError("state payload missing iat")
    if (int(time.time()) - iat) > ttl:
        raise ValueError("state token expired")
    return StatePayload(
        nonce=body.get("nonce", ""),
        provider=body.get("provider", ""),
        redirect_uri=body.get("redirect_uri", ""),
        next_url=body.get("next_url", "/"),
        # Present only when this token came from the state COOKIE (signed with
        # ``include_verifier=True``); absent for the URL ``state=`` token.
        code_verifier=body.get("code_verifier", ""),
        iat=iat,
    )


def new_nonce() -> str:
    """32 bytes of url-safe random — used as the state ``nonce`` field."""
    return secrets.token_urlsafe(32)


__all__ = ["StatePayload", "new_nonce", "sign_state", "verify_state"]
