# Changelog

## 0.2.0 — 2026-06-10

Security hardening.

This release is a behavior and compatibility change: it adds a new required dependency, `PyJWT[crypto]`, and OIDC providers now cryptographically validate the `id_token` on callback (a misconfigured provider that previously "worked" may now be rejected).

- OIDC ID tokens are now cryptographically validated: the signature is verified against the provider JWKS, plus `iss` / `aud` / `exp` / `nonce` checks, and the validated `sub` is treated as the authoritative identity (it was previously accepted unverified — CWE-347). Added the `PyJWT[crypto]` dependency. A `nonce` is now sent on the authorize request for OIDC providers.
- PKCE `code_verifier` is no longer placed in the `state` value sent to the provider; it is kept only in the server-side state cookie, which is never transmitted to the authorization server (CWE-200).
- The callback `redirect_uri` derived from the request `Host` header is validated against a configurable `allowed_hosts` allowlist; `base_url` can pin it explicitly (CWE-601 / SSRF).
- The OAuth `error` callback parameter is now handled — the state cookie is cleared and the user is redirected to `failure_redirect` instead of returning a misleading 400.
- State validation failures return a generic `invalid state` detail; the underlying reason is logged internally rather than leaked to the client (CWE-209).
- Provider `token_url` / `userinfo_url` / `jwks_url` must be HTTPS, and the HTTP client no longer follows redirects (SSRF hardening — CWE-918).
- `OAuthToken.__repr__` masks the access / refresh / id tokens and the raw token body (CWE-532).
- `next` redirect validation now rejects any value carrying a scheme or netloc and normalizes backslashes, which some browsers treat as `/` (open redirect — CWE-601).

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
