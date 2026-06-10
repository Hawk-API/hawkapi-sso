"""Microsoft Entra (Azure AD) OAuth2 / OIDC provider."""

from __future__ import annotations

from dataclasses import dataclass, field

from ._base import OAuthError, OAuthProvider, OAuthToken, OAuthUser


@dataclass(kw_only=True)
class MicrosoftProvider(OAuthProvider):
    name: str = "microsoft"
    tenant: str = "common"  # "common" / "organizations" / "consumers" / tenant GUID
    authorization_url: str = ""
    token_url: str = ""
    userinfo_url: str = "https://graph.microsoft.com/oidc/userinfo"
    jwks_url: str = ""
    issuer: str = ""
    is_oidc: bool = True
    default_scopes: list[str] = field(
        default_factory=lambda: ["openid", "email", "profile", "User.Read"]
    )
    supports_pkce: bool = True

    def __post_init__(self) -> None:
        # Use v2.0 endpoints. Tenant is templated in at construction time.
        base = f"https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0"
        if not self.authorization_url:
            self.authorization_url = f"{base}/authorize"
        if not self.token_url:
            self.token_url = f"{base}/token"
        if not self.jwks_url:
            self.jwks_url = f"{base}/keys"
        # The v2.0 token ``iss`` embeds the resolved tenant GUID, so it is only a
        # fixed string for a concrete tenant. For the multi-tenant aliases
        # ("common"/"organizations"/"consumers") the issuer varies per token; leave
        # it empty to skip strict ``iss`` matching (signature/aud/exp/nonce still
        # enforced).
        if not self.issuer and self.tenant not in ("common", "organizations", "consumers"):
            self.issuer = f"https://login.microsoftonline.com/{self.tenant}/v2.0"
        super().__post_init__()

    async def fetch_userinfo(self, token: OAuthToken) -> OAuthUser:
        client = self._get_client()
        resp = await client.get(
            self.userinfo_url,
            headers={"Authorization": f"Bearer {token.access_token}"},
        )
        if resp.status_code >= 300:
            raise OAuthError(f"microsoft userinfo failed: HTTP {resp.status_code}")
        body = resp.json()
        if not isinstance(body, dict) or "sub" not in body:
            raise OAuthError("microsoft userinfo missing sub")
        # The v2.0 userinfo endpoint returns standard OIDC claims;
        # email_verified is implied for organizational accounts but not always present.
        return OAuthUser(
            provider="microsoft",
            sub=str(body["sub"]),
            email=str(body.get("email", "")),
            # Microsoft v2.0 userinfo includes ``email_verified`` for org accounts
            # but omits it for personal accounts. Default to False — consumers
            # may treat tenant-bound accounts as verified by policy.
            email_verified=bool(body.get("email_verified", False)),
            name=str(body.get("name", "")),
            picture=str(body.get("picture", "")),
            raw=body,
        )


__all__ = ["MicrosoftProvider"]
