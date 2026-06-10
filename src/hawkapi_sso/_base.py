"""OAuth provider abstraction + normalized user record."""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Any

import httpx

from ._oidc import OIDCError, verify_id_token


class OAuthError(Exception):
    """Raised by any provider when the OAuth exchange fails."""


def _mask(value: str) -> str:
    """Redact a secret for ``repr`` — keep length signal, never the value."""
    return f"<redacted {len(value)} chars>" if value else ""


@dataclass(slots=True)
class OAuthToken:
    access_token: str
    token_type: str = "Bearer"
    expires_in: int = 0
    refresh_token: str = ""
    id_token: str = ""
    scope: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        # Never leak bearer/refresh/id tokens (or ``raw``, which contains them)
        # into logs or tracebacks.
        return (
            f"OAuthToken(access_token={_mask(self.access_token)!r}, "
            f"token_type={self.token_type!r}, expires_in={self.expires_in}, "
            f"refresh_token={_mask(self.refresh_token)!r}, "
            f"id_token={_mask(self.id_token)!r}, scope={self.scope!r}, "
            f"raw=<redacted>)"
        )


@dataclass(slots=True)
class OAuthUser:
    provider: str
    sub: str
    email: str = ""
    email_verified: bool = False
    name: str = ""
    picture: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(kw_only=True)
class OAuthProvider:
    """Abstract base — subclass per provider and override the four endpoint URLs."""

    name: str = ""
    client_id: str = ""
    client_secret: str = ""
    authorization_url: str = ""
    token_url: str = ""
    userinfo_url: str = ""
    default_scopes: list[str] = field(default_factory=list)
    supports_pkce: bool = False
    # OIDC: when ``is_oidc`` is set the ``id_token`` from the token exchange is
    # verified against ``jwks_url`` (signature + iss/aud/exp/nonce). Pure OAuth2
    # providers leave these unset and skip ID-token validation entirely.
    is_oidc: bool = False
    jwks_url: str = ""
    issuer: str = ""
    timeout: float = 10.0
    _client: httpx.AsyncClient | None = field(default=None, init=False)
    _jwks_cache: dict[str, Any] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        self._validate_urls()

    def _validate_urls(self) -> None:
        # SSRF hardening: the endpoints we POST credentials / bearer tokens to
        # must be https. Subclasses that template URLs late call this again.
        from urllib.parse import urlparse

        for label, url in (
            ("token_url", self.token_url),
            ("userinfo_url", self.userinfo_url),
            ("jwks_url", self.jwks_url),
        ):
            if url and urlparse(url).scheme != "https":
                who = self.name or type(self).__name__
                raise ValueError(f"{who} {label} must be https: {url!r}")

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            # follow_redirects=False — never let a token/userinfo endpoint bounce
            # our credentials or bearer token to an attacker-controlled host.
            self._client = httpx.AsyncClient(timeout=self.timeout, follow_redirects=False)
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def build_authorize_url(
        self,
        *,
        redirect_uri: str,
        state: str,
        scopes: list[str] | None = None,
        code_challenge: str = "",
        nonce: str = "",
        extra: dict[str, str] | None = None,
    ) -> str:
        """Compose the authorization URL the user is redirected to."""
        from urllib.parse import urlencode

        params: dict[str, str] = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes or self.default_scopes),
            "state": state,
        }
        if code_challenge and self.supports_pkce:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"
        # OIDC nonce binds the id_token to this login; validated on callback.
        if nonce and self.is_oidc:
            params["nonce"] = nonce
        if extra:
            params.update({k: str(v) for k, v in extra.items() if v != ""})
        return f"{self.authorization_url}?{urlencode(params)}"

    async def exchange_code(
        self,
        code: str,
        *,
        redirect_uri: str,
        code_verifier: str = "",
    ) -> OAuthToken:
        """Trade an authorization code for an access token."""
        data: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        if code_verifier and self.supports_pkce:
            data["code_verifier"] = code_verifier
        client = self._get_client()
        resp = await client.post(
            self.token_url,
            data=data,
            headers={"Accept": "application/json"},
        )
        if resp.status_code >= 300:
            # Never include client_secret in the error message.
            raise OAuthError(f"{self.name} token exchange failed: HTTP {resp.status_code}")
        try:
            body = resp.json()
        except ValueError as exc:
            raise OAuthError(f"{self.name} returned non-JSON token response") from exc
        if not isinstance(body, dict):
            raise OAuthError(f"{self.name} returned non-object token response")
        if "access_token" not in body:
            raise OAuthError(f"{self.name} token response missing access_token")
        return OAuthToken(
            access_token=body["access_token"],
            token_type=body.get("token_type", "Bearer"),
            expires_in=int(body.get("expires_in", 0) or 0),
            refresh_token=body.get("refresh_token", "") or "",
            id_token=body.get("id_token", "") or "",
            scope=body.get("scope", "") or "",
            raw=body,
        )

    async def _fetch_jwks(self) -> dict[str, Any]:
        """Fetch and cache the provider JWK set (used to verify id_tokens)."""
        if not self._jwks_cache:
            client = self._get_client()
            resp = await client.get(self.jwks_url, headers={"Accept": "application/json"})
            if resp.status_code >= 300:
                raise OAuthError(f"{self.name} JWKS fetch failed: HTTP {resp.status_code}")
            body = resp.json()
            if not isinstance(body, dict) or "keys" not in body:
                raise OAuthError(f"{self.name} JWKS response malformed")
            self._jwks_cache = body
        return self._jwks_cache

    async def verify_id_token(self, token: OAuthToken, *, nonce: str) -> dict[str, Any]:
        """Validate the OIDC ``id_token`` and return its claims.

        Verifies signature against ``jwks_url`` plus ``iss``, ``aud == client_id``,
        ``exp`` and ``nonce``. Only invoked for OIDC providers; the validated
        ``sub`` is the authoritative identity. Raises :class:`OAuthError`.
        """
        if not self.is_oidc:
            return {}
        if not self.jwks_url:
            raise OAuthError(f"{self.name} is_oidc but has no jwks_url")
        jwks = await self._fetch_jwks()
        try:
            return verify_id_token(
                token.id_token,
                jwks=jwks,
                issuer=self.issuer,
                audience=self.client_id,
                nonce=nonce,
            )
        except OIDCError as exc:
            raise OAuthError(f"{self.name} id_token validation failed: {exc}") from exc

    async def fetch_userinfo(self, token: OAuthToken) -> OAuthUser:
        """Provider-specific. Override in subclasses."""
        raise NotImplementedError


def make_pkce() -> tuple[str, str]:
    """Return (verifier, challenge). RFC 7636."""
    verifier = secrets.token_urlsafe(48)[:128]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


__all__ = [
    "OAuthError",
    "OAuthProvider",
    "OAuthToken",
    "OAuthUser",
    "make_pkce",
]
