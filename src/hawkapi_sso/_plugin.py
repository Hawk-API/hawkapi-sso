"""init_sso(app, ...) — plugin orchestrator + DI."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from weakref import WeakKeyDictionary

from hawkapi import HTTPException, Request

from ._base import OAuthProvider


class _StateNamespace:
    sso: Any


@dataclass
class SSOConfig:
    providers: dict[str, OAuthProvider] = field(default_factory=dict)
    state_secret: str = ""
    cookie_name: str = "hawkapi_sso_state"
    cookie_secure: bool = True
    cookie_samesite: str = "lax"
    cookie_max_age: int = 600
    state_ttl_seconds: int = 600
    login_path_prefix: str = "/auth/sso"
    success_redirect: str = "/"
    failure_redirect: str = "/login?error=sso"
    # When set, only these hosts may be used to derive a callback ``redirect_uri``
    # from the request ``Host`` header. Pinning ``provider._redirect_uri`` is
    # preferred; this allowlist guards the Host-derived fallback (CWE-601/CWE-918).
    allowed_hosts: tuple[str, ...] = ()
    base_url: str = ""


_ACTIVE: WeakKeyDictionary[Any, SSOConfig] = WeakKeyDictionary()
_LAST: list[SSOConfig | None] = [None]


def init_sso(
    app: Any,
    *,
    providers: dict[str, OAuthProvider],
    state_secret: str,
    cookie_name: str = "hawkapi_sso_state",
    cookie_secure: bool = True,
    cookie_samesite: str = "lax",
    cookie_max_age: int = 600,
    login_path_prefix: str = "/auth/sso",
    success_redirect: str = "/",
    failure_redirect: str = "/login?error=sso",
    allowed_hosts: tuple[str, ...] = (),
    base_url: str = "",
) -> SSOConfig:
    """Attach SSO to ``app.state.sso`` and register OAuth routes.

    ``state_secret`` MUST be a stable, secret value (≥32 bytes recommended) used
    to sign the state token cookie. Re-deploying with a new value will invalidate
    every pending OAuth flow.
    """
    if not state_secret or len(state_secret) < 32:
        raise ValueError("state_secret must be at least 32 characters")
    if not providers:
        raise ValueError("at least one provider must be registered")

    cfg = SSOConfig(
        providers=dict(providers),
        state_secret=state_secret,
        cookie_name=cookie_name,
        cookie_secure=cookie_secure,
        cookie_samesite=cookie_samesite.lower(),
        cookie_max_age=cookie_max_age,
        login_path_prefix=login_path_prefix.rstrip("/"),
        success_redirect=success_redirect,
        failure_redirect=failure_redirect,
        allowed_hosts=tuple(allowed_hosts),
        base_url=base_url.rstrip("/"),
    )
    if getattr(app, "state", None) is None:
        app.state = _StateNamespace()
    app.state.sso = cfg
    try:
        _ACTIVE[app] = cfg
    except TypeError:
        pass
    _LAST[0] = cfg

    # Wire routes lazily — the routes module imports this module, so do it here
    # to avoid an import cycle at module-load time.
    from ._routes import attach_routes

    attach_routes(app, cfg)

    if hasattr(app, "on_shutdown"):

        async def _close_providers() -> None:
            for p in cfg.providers.values():
                await p.close()

        app.on_shutdown(_close_providers)

    return cfg


def resolve_sso(app: Any) -> SSOConfig | None:
    if app is None:
        return _LAST[0]
    try:
        found = _ACTIVE.get(app)
    except TypeError:
        found = None
    if found is not None:
        return found
    state = getattr(app, "state", None)
    if state is not None and hasattr(state, "sso"):
        return state.sso  # type: ignore[no-any-return]
    return _LAST[0]


def get_sso(request: Request) -> SSOConfig:
    cfg = resolve_sso(request.scope.get("app"))
    if cfg is None:
        raise HTTPException(500, detail="SSO not configured — call init_sso(app, ...) first")
    return cfg


__all__ = ["SSOConfig", "get_sso", "init_sso", "resolve_sso"]
