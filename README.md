# hawkapi-sso

Social SSO for [HawkAPI](https://github.com/Hawk-API/HawkAPI). One plugin, six providers:

- **Google** (OAuth2 + OIDC, PKCE)
- **GitHub** (OAuth2)
- **Microsoft / Entra** (OAuth2 + OIDC, PKCE)
- **Discord** (OAuth2)
- **Facebook** (OAuth2 + Graph API)
- **LinkedIn** (OAuth2 + OIDC, PKCE)

Pure-Python, async, `httpx`-based. CSRF-protected via HMAC-signed state cookie. PKCE applied automatically where the provider supports it.

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
- **CSRF** — the callback rejects requests whose `state` query parameter does not match the state cookie byte-for-byte.
- **PKCE** — automatically generated and verified for Google, Microsoft, LinkedIn.
- **Open-redirect guard** — `?next=` parameter must be a path (`/...`); anything else falls back to `success_redirect`.
- **`client_secret`** — never logged, never returned in any URL or response.
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
)
```

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
