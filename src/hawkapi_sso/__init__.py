"""hawkapi-sso — Social SSO for HawkAPI.

Provides OAuth2 / OIDC integration for Google, GitHub, Microsoft (Entra),
Discord, Facebook, and LinkedIn. Single ``init_sso(app, ...)`` entry point;
routes mounted at ``/auth/sso/login/{provider}`` and
``/auth/sso/callback/{provider}`` by default. Every flow is CSRF-protected
via an HMAC-signed state cookie; PKCE is used where the provider supports
it.
"""

from __future__ import annotations

from ._base import OAuthError, OAuthProvider, OAuthToken, OAuthUser, make_pkce
from ._discord import DiscordProvider
from ._facebook import FacebookProvider
from ._github import GitHubProvider
from ._google import GoogleProvider
from ._linkedin import LinkedInProvider
from ._microsoft import MicrosoftProvider
from ._plugin import SSOConfig, get_sso, init_sso, resolve_sso
from ._state import StatePayload, new_nonce, sign_state, verify_state

__version__ = "0.1.0"

__all__ = [
    "DiscordProvider",
    "FacebookProvider",
    "GitHubProvider",
    "GoogleProvider",
    "LinkedInProvider",
    "MicrosoftProvider",
    "OAuthError",
    "OAuthProvider",
    "OAuthToken",
    "OAuthUser",
    "SSOConfig",
    "StatePayload",
    "__version__",
    "get_sso",
    "init_sso",
    "make_pkce",
    "new_nonce",
    "resolve_sso",
    "sign_state",
    "verify_state",
]
