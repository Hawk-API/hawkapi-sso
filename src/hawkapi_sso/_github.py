"""GitHub OAuth2 provider."""

from __future__ import annotations

from dataclasses import dataclass, field

from ._base import OAuthError, OAuthProvider, OAuthToken, OAuthUser


@dataclass(kw_only=True)
class GitHubProvider(OAuthProvider):
    name: str = "github"
    authorization_url: str = "https://github.com/login/oauth/authorize"
    token_url: str = "https://github.com/login/oauth/access_token"
    userinfo_url: str = "https://api.github.com/user"
    emails_url: str = "https://api.github.com/user/emails"
    default_scopes: list[str] = field(default_factory=lambda: ["read:user", "user:email"])
    supports_pkce: bool = False  # not documented as supported

    async def fetch_userinfo(self, token: OAuthToken) -> OAuthUser:
        client = self._get_client()
        headers = {
            "Authorization": f"Bearer {token.access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        u = await client.get(self.userinfo_url, headers=headers)
        if u.status_code >= 300:
            raise OAuthError(f"github userinfo failed: HTTP {u.status_code}")
        user = u.json()
        if not isinstance(user, dict) or "id" not in user:
            raise OAuthError("github userinfo missing id")

        email = str(user.get("email") or "")
        email_verified = False
        if not email:
            er = await client.get(self.emails_url, headers=headers)
            if er.status_code < 300:
                emails = er.json() or []
                if isinstance(emails, list):
                    primary = next(
                        (e for e in emails if isinstance(e, dict) and e.get("primary")),
                        None,
                    )
                    if primary:
                        email = str(primary.get("email", "") or "")
                        email_verified = bool(primary.get("verified", False))
        else:
            # Re-check verification status against the addresses endpoint.
            er = await client.get(self.emails_url, headers=headers)
            if er.status_code < 300:
                emails = er.json() or []
                if isinstance(emails, list):
                    for e in emails:
                        if isinstance(e, dict) and e.get("email") == email:
                            email_verified = bool(e.get("verified", False))
                            break

        return OAuthUser(
            provider="github",
            sub=str(user["id"]),
            email=email,
            email_verified=email_verified,
            name=str(user.get("name", "") or user.get("login", "")),
            picture=str(user.get("avatar_url", "")),
            raw=user,
        )


__all__ = ["GitHubProvider"]
