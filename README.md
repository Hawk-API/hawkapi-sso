# hawkapi-sso

Social SSO for [HawkAPI](https://github.com/Hawk-API/HawkAPI). One plugin, six providers:

- **Google** (OAuth2 + OIDC, PKCE)
- **GitHub** (OAuth2)
- **Microsoft / Entra** (OAuth2 + OIDC, PKCE)
- **Discord** (OAuth2)
- **Facebook** (OAuth2 + Graph API)
- **LinkedIn** (OAuth2 + OIDC, PKCE)

Pure-Python, async, `httpx`-based. CSRF-protected via HMAC-signed state cookie. PKCE applied automatically where the provider supports it. OIDC `id_token`s are cryptographically validated against the provider JWKS.

## Install

```bash
pip install hawkapi-sso
```

## Quickstart

```python
from hawkapi import HawkAPI
from hawkapi_sso import GoogleProvider, GitHubProvider, init_sso

app = HawkAPI()
init_sso(
    app,
    providers={
        "google": GoogleProvider(client_id="...", client_secret="..."),
        "github": GitHubProvider(client_id="...", client_secret="..."),
    },
    state_secret="...",            # ≥16 chars; stable across restarts
)


# These routes are mounted automatically:
# GET /auth/sso/login/{provider}     → redirects to the provider's authorize URL
# GET /auth/sso/callback/{provider}  → handles the OAuth callback, sets `request.scope["sso_user"]`,
#                                       then redirects to `?next=` (or success_redirect).
```

## Reading the authenticated user

The callback handler stashes a normalized `OAuthUser` on the request scope. Pick it up in your downstream middleware / handlers:

```python
@app.middleware("http")
async def persist_session(request, call_next):
    response = await call_next(request)
    user = request.scope.get("sso_user")
    if user is not None:
        # persist user, set session cookie, etc.
        ...
    return response
```

You can also wire a callback hook:

```python
async def on_login(request, user, token):
    # persist, mint JWT, etc.
    ...

cfg = init_sso(app, providers={...}, state_secret="...")
cfg.on_success = on_login
```

## OAuthUser

```python
@dataclass
class OAuthUser:
    provider: str         # "google" / "github" / ...
    sub: str              # provider-issued user id (always string)
    email: str            # "" if not granted
    email_verified: bool  # only True when the provider explicitly signals it
    name: str
    picture: str
    raw: dict             # the parsed userinfo response, for advanced use
```

## Security

- **State cookie** — `HttpOnly`, `Secure` (configurable), `SameSite=Lax`, `Max-Age=600` by default. Signed with HMAC-SHA256 over the state secret.
- **CSRF** — the callback validates the signed `state` from the URL against the signed state cookie and requires their nonces to match. State validation failures return a generic `invalid state`; the underlying reason is logged internally, not leaked to the client.
- **OIDC ID-token validation** — for OIDC providers (Google, Microsoft, LinkedIn) the `id_token` is cryptographically verified on callback: signature against the provider JWKS, plus `iss` / `aud` / `exp` / `nonce`. The validated `sub` is treated as the authoritative identity. A `nonce` is sent on the authorize request and bound to the login. This requires `PyJWT[crypto]` (a required dependency).
- **PKCE** — automatically generated and verified for Google, Microsoft, LinkedIn. The `code_verifier` is kept only in the server-side state cookie and is never placed in the `state` sent to the provider.
- **Provider URLs** — `token_url` / `userinfo_url` / `jwks_url` must be HTTPS; the HTTP client does not follow redirects.
- **Provider `error`** — when the provider aborts the flow (e.g. user denied consent), the callback clears the state cookie and redirects to `failure_redirect` instead of returning a misleading 400.
- **Open-redirect guard** — `?next=` parameter must be a same-site path (`/...`); any value carrying a scheme or netloc is rejected (backslashes are normalized to `/`), falling back to `success_redirect`.
- **`client_secret`** — never logged, never returned in any URL or response. Access / refresh / ID tokens are masked in `OAuthToken` reprs.
- **Email verification** — `email_verified=True` is set only when the provider explicitly signals it (GitHub uses the `/user/emails` endpoint). Facebook does not, so it defaults to `False`.

## Configuration

```python
init_sso(
    app,
    providers={...},
    state_secret="...",
    cookie_name="hawkapi_sso_state",
    cookie_secure=True,
    cookie_samesite="lax",
    cookie_max_age=600,
    login_path_prefix="/auth/sso",
    success_redirect="/",
    failure_redirect="/login?error=sso",
    allowed_hosts=(),              # allowlist for Host-derived redirect_uri
    base_url="",                   # pin the redirect base, e.g. "https://app.example.com"
)
```

### Redirect-URI safety

The callback `redirect_uri` is resolved in this order:

1. `provider._redirect_uri`, if pinned on the provider (preferred);
2. `base_url` — set it to your public origin (e.g. `https://app.example.com`) to pin the redirect base explicitly;
3. the request `Host` header — used only as a fallback, and only when the Host is listed in `allowed_hosts`.

Set `base_url`, or pin the provider's `redirect_uri`, for production. If you must rely on the Host header, list every accepted host in `allowed_hosts`; an unlisted Host is rejected. This prevents an attacker-controlled `Host` from steering the OAuth `redirect_uri` (host-header / open-redirect / SSRF, CWE-601 / CWE-918).

## Development

```bash
git clone https://github.com/Hawk-API/hawkapi-sso.git
cd hawkapi-sso
uv sync --extra dev
uv run pytest -q
uv run ruff check . && uv run ruff format --check .
uv run pyright src/
```

## License

MIT.
