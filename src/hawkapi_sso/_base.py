"""OAuth provider abstraction + normalized user record."""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Any

import httpx


class OAuthError(Exception):
    """Raised by any provider when the OAuth exchange fails."""


@dataclass(slots=True)
class OAuthToken:
    access_token: str
    token_type: str = "Bearer"
    expires_in: int = 0
    refresh_token: str = ""
    id_token: str = ""
    scope: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


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
    timeout: float = 10.0
    _client: httpx.AsyncClient | None = field(default=None, init=False)

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout)
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
