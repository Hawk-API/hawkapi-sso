"""Discord OAuth2 provider."""

from __future__ import annotations

from dataclasses import dataclass, field

from ._base import OAuthError, OAuthProvider, OAuthToken, OAuthUser


@dataclass(kw_only=True)
class DiscordProvider(OAuthProvider):
    name: str = "discord"
    authorization_url: str = "https://discord.com/api/oauth2/authorize"
    token_url: str = "https://discord.com/api/oauth2/token"
    userinfo_url: str = "https://discord.com/api/users/@me"
    default_scopes: list[str] = field(default_factory=lambda: ["identify", "email"])
    supports_pkce: bool = False

    async def fetch_userinfo(self, token: OAuthToken) -> OAuthUser:
        client = self._get_client()
        resp = await client.get(
            self.userinfo_url,
            headers={"Authorization": f"Bearer {token.access_token}"},
        )
        if resp.status_code >= 300:
            raise OAuthError(f"discord userinfo failed: HTTP {resp.status_code}")
        body = resp.json()
        if not isinstance(body, dict) or "id" not in body:
            raise OAuthError("discord userinfo missing id")
        avatar = body.get("avatar")
        picture = ""
        if avatar:
            picture = f"https://cdn.discordapp.com/avatars/{body['id']}/{avatar}.png"
        return OAuthUser(
            provider="discord",
            sub=str(body["id"]),
            email=str(body.get("email", "")),
            email_verified=bool(body.get("verified", False)),
            name=str(body.get("global_name") or body.get("username") or ""),
            picture=picture,
            raw=body,
        )


__all__ = ["DiscordProvider"]
