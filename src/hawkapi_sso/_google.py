"""Google OAuth2 / OpenID Connect provider."""

from __future__ import annotations

from dataclasses import dataclass, field

from ._base import OAuthError, OAuthProvider, OAuthToken, OAuthUser


@dataclass(kw_only=True)
class GoogleProvider(OAuthProvider):
    name: str = "google"
    authorization_url: str = "https://accounts.google.com/o/oauth2/v2/auth"
    token_url: str = "https://oauth2.googleapis.com/token"
    userinfo_url: str = "https://openidconnect.googleapis.com/v1/userinfo"
    jwks_url: str = "https://www.googleapis.com/oauth2/v3/certs"
    issuer: str = "https://accounts.google.com"
    is_oidc: bool = True
    default_scopes: list[str] = field(default_factory=lambda: ["openid", "email", "profile"])
    supports_pkce: bool = True

    async def fetch_userinfo(self, token: OAuthToken) -> OAuthUser:
        client = self._get_client()
        resp = await client.get(
            self.userinfo_url,
            headers={"Authorization": f"Bearer {token.access_token}"},
        )
        if resp.status_code >= 300:
            raise OAuthError(f"google userinfo failed: HTTP {resp.status_code}")
        try:
            body = resp.json()
        except ValueError as exc:
            raise OAuthError("google userinfo returned non-JSON") from exc
        if not isinstance(body, dict) or "sub" not in body:
            raise OAuthError("google userinfo missing sub")
        return OAuthUser(
            provider="google",
            sub=str(body["sub"]),
            email=str(body.get("email", "")),
            email_verified=bool(body.get("email_verified", False)),
            name=str(body.get("name", "")),
            picture=str(body.get("picture", "")),
            raw=body,
        )


__all__ = ["GoogleProvider"]
