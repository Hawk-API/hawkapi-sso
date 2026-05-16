"""Facebook OAuth2 provider (Graph API)."""

from __future__ import annotations

from dataclasses import dataclass, field

from ._base import OAuthError, OAuthProvider, OAuthToken, OAuthUser


@dataclass(kw_only=True)
class FacebookProvider(OAuthProvider):
    name: str = "facebook"
    authorization_url: str = "https://www.facebook.com/v18.0/dialog/oauth"
    token_url: str = "https://graph.facebook.com/v18.0/oauth/access_token"
    userinfo_url: str = "https://graph.facebook.com/me"
    default_scopes: list[str] = field(default_factory=lambda: ["email", "public_profile"])
    supports_pkce: bool = False
    fields: str = "id,name,email,picture"

    async def fetch_userinfo(self, token: OAuthToken) -> OAuthUser:
        client = self._get_client()
        # Use the Authorization header — query-string tokens leak via Referer,
        # browser history, and load-balancer access logs.
        resp = await client.get(
            self.userinfo_url,
            params={"fields": self.fields},
            headers={"Authorization": f"Bearer {token.access_token}"},
        )
        if resp.status_code >= 300:
            raise OAuthError(f"facebook userinfo failed: HTTP {resp.status_code}")
        body = resp.json()
        if not isinstance(body, dict) or "id" not in body:
            raise OAuthError("facebook userinfo missing id")
        picture = ""
        pic_blob = body.get("picture")
        if isinstance(pic_blob, dict) and isinstance(pic_blob.get("data"), dict):
            picture = str(pic_blob["data"].get("url", ""))
        # Facebook does not return a verified flag here — assume False unless the
        # caller has done extra validation.
        return OAuthUser(
            provider="facebook",
            sub=str(body["id"]),
            email=str(body.get("email", "")),
            email_verified=False,
            name=str(body.get("name", "")),
            picture=picture,
            raw=body,
        )


__all__ = ["FacebookProvider"]
