"""LinkedIn OAuth2 / OIDC provider."""

from __future__ import annotations

from dataclasses import dataclass, field

from ._base import OAuthError, OAuthProvider, OAuthToken, OAuthUser


@dataclass(kw_only=True)
class LinkedInProvider(OAuthProvider):
    name: str = "linkedin"
    authorization_url: str = "https://www.linkedin.com/oauth/v2/authorization"
    token_url: str = "https://www.linkedin.com/oauth/v2/accessToken"
    userinfo_url: str = "https://api.linkedin.com/v2/userinfo"
    default_scopes: list[str] = field(default_factory=lambda: ["openid", "profile", "email"])
    supports_pkce: bool = True

    async def fetch_userinfo(self, token: OAuthToken) -> OAuthUser:
        client = self._get_client()
        resp = await client.get(
            self.userinfo_url,
            headers={"Authorization": f"Bearer {token.access_token}"},
        )
        if resp.status_code >= 300:
            raise OAuthError(f"linkedin userinfo failed: HTTP {resp.status_code}")
        body = resp.json()
        if not isinstance(body, dict) or "sub" not in body:
            raise OAuthError("linkedin userinfo missing sub")
        return OAuthUser(
            provider="linkedin",
            sub=str(body["sub"]),
            email=str(body.get("email", "")),
            email_verified=bool(body.get("email_verified", False)),
            name=str(body.get("name", "")),
            picture=str(body.get("picture", "")),
            raw=body,
        )


__all__ = ["LinkedInProvider"]
