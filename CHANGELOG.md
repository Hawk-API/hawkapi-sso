# Changelog

## 0.1.0 — 2026-05-16

Initial release.

Security review applied before ship:

- Open-redirect via protocol-relative `?next=//host/path` is blocked (CWE-601).
- State cookie cleared on success even when an `on_success` hook returns its own response (CWE-384, prevents replay within the 10-minute TTL).
- Microsoft `email_verified` defaults to `False` when the claim is absent — no implicit promotion of unverified personal-account emails.
- Facebook userinfo sends the access token via `Authorization: Bearer`, not in the query string (CWE-598, prevents token leakage to access logs / Referer).
- `state_secret` minimum enforced at 32 characters (was 16); matches the documented recommendation.

Features:

- Six providers: Google, GitHub, Microsoft / Entra, Discord, Facebook, LinkedIn.
- HMAC-signed state cookie (`HttpOnly`, `Secure`, `SameSite=Lax`, 10-minute TTL) defeats CSRF on the OAuth callback.
- PKCE applied automatically for Google, Microsoft, LinkedIn.
- GitHub email verification fetched via `/user/emails`; flagged correctly when unverified.
- Normalized `OAuthUser` across all providers — `sub` / `email` / `email_verified` / `name` / `picture` / `raw`.
- Routes mounted at `/auth/sso/login/{provider}` and `/auth/sso/callback/{provider}` (prefix configurable).
- `init_sso(app, ...)` + `Depends(get_sso)` + `WeakKeyDictionary` registry.
- `client_secret` is never logged or returned in any error response.
