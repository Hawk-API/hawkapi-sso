"""Login + callback handlers wired by :func:`init_sso`."""

from __future__ import annotations

from typing import Any

from hawkapi import HTTPException, Request
from hawkapi.responses import RedirectResponse

from ._base import OAuthUser, make_pkce
from ._state import StatePayload, new_nonce, sign_state, verify_state


def _provider_or_404(cfg: Any, name: str) -> Any:
    provider = cfg.providers.get(name)
    if provider is None:
        raise HTTPException(404, detail=f"unknown SSO provider {name!r}")
    return provider


def _cookie_attrs(cfg: Any) -> str:
    parts = [
        f"Max-Age={cfg.cookie_max_age}",
        "Path=/",
        "HttpOnly",
    ]
    if cfg.cookie_secure:
        parts.append("Secure")
    samesite = cfg.cookie_samesite or "lax"
    parts.append(f"SameSite={samesite.capitalize()}")
    return "; ".join(parts)


def _redirect_with_cookie(url: str, *, name: str, value: str, attrs: str) -> RedirectResponse:
    resp = RedirectResponse(url, status_code=302)
    resp.headers["set-cookie"] = f"{name}={value}; {attrs}"
    return resp


def _clear_cookie(resp: RedirectResponse, *, name: str, secure: bool, samesite: str) -> None:
    attrs = [
        "Max-Age=0",
        "Path=/",
        "HttpOnly",
    ]
    if secure:
        attrs.append("Secure")
    attrs.append(f"SameSite={(samesite or 'lax').capitalize()}")
    resp.headers["set-cookie"] = f"{name}=; " + "; ".join(attrs)


def _read_cookie(request: Request, name: str) -> str:
    raw = request.headers.get("cookie", "") if hasattr(request, "headers") else ""
    if not raw:
        return ""
    for chunk in raw.split(";"):
        k, _, v = chunk.strip().partition("=")
        if k == name:
            return v
    return ""


def attach_routes(app: Any, cfg: Any) -> None:
    """Register ``/login/{provider}`` and ``/callback/{provider}`` on ``app``."""
    prefix = cfg.login_path_prefix

    async def _login(request: Request) -> Any:
        provider_name = str(request.path_params["provider"])
        provider = _provider_or_404(cfg, provider_name)
        # next_url is the in-app URL we redirect to on success — never a full URL.
        # Reject ``//host/path`` (protocol-relative) which the browser resolves to
        # https://host/path, off-site (CWE-601).
        next_url = request.query_params.get("next", cfg.success_redirect)
        if (
            not isinstance(next_url, str)
            or not next_url.startswith("/")
            or next_url.startswith("//")
        ):
            next_url = cfg.success_redirect

        # PKCE — only meaningful where the provider supports it.
        verifier = ""
        challenge = ""
        if provider.supports_pkce:
            verifier, challenge = make_pkce()

        # Redirect URI must point back at this app's callback for this provider.
        # The host header is taken at face value — HawkAPI deployments are expected
        # to sit behind TrustedProxy middleware that validates Host. The operator
        # can pin a fixed callback URL by setting ``provider._redirect_uri``.
        from urllib.parse import urlparse

        raw_url = getattr(request, "url", "")
        scheme = urlparse(str(raw_url)).scheme or "https"
        host = request.headers.get("host", "")
        redirect_uri = (
            getattr(provider, "_redirect_uri", "")
            or f"{scheme}://{host}{prefix}/callback/{provider_name}"
        )

        payload = StatePayload(
            nonce=new_nonce(),
            provider=provider_name,
            redirect_uri=redirect_uri,
            next_url=next_url,
            code_verifier=verifier,
        )
        signed = sign_state(payload, secret=cfg.state_secret)
        url = provider.build_authorize_url(
            redirect_uri=redirect_uri,
            state=signed,
            code_challenge=challenge,
        )
        return _redirect_with_cookie(
            url,
            name=cfg.cookie_name,
            value=signed,
            attrs=_cookie_attrs(cfg),
        )

    async def _callback(request: Request) -> Any:
        provider_name = str(request.path_params["provider"])
        provider = _provider_or_404(cfg, provider_name)
        state_q = request.query_params.get("state", "")
        state_c = _read_cookie(request, cfg.cookie_name)
        code = request.query_params.get("code", "")

        # CSRF: state from query must equal state cookie, byte-for-byte.
        if not code or not state_q or not state_c or state_q != state_c:
            raise HTTPException(400, detail="bad state")

        try:
            payload = verify_state(
                state_q,
                secret=cfg.state_secret,
                ttl=cfg.state_ttl_seconds,
            )
        except ValueError as exc:
            raise HTTPException(400, detail=f"bad state: {exc}") from exc

        if payload.provider != provider_name:
            raise HTTPException(400, detail="state provider mismatch")

        token = await provider.exchange_code(
            code,
            redirect_uri=payload.redirect_uri,
            code_verifier=payload.code_verifier,
        )
        user = await provider.fetch_userinfo(token)

        on_success = getattr(cfg, "on_success", None)
        if callable(on_success):
            # User hook to persist / set a session. We don't override its return.
            result = await on_success(request, user, token)
            if result is not None:
                # Clear the state cookie on the hook's response too so it cannot
                # be replayed within the 10-minute TTL window.
                if hasattr(result, "headers"):
                    _clear_cookie(
                        result,
                        name=cfg.cookie_name,
                        secure=cfg.cookie_secure,
                        samesite=cfg.cookie_samesite,
                    )
                return result

        resp = RedirectResponse(payload.next_url or cfg.success_redirect, status_code=302)
        _clear_cookie(
            resp,
            name=cfg.cookie_name,
            secure=cfg.cookie_secure,
            samesite=cfg.cookie_samesite,
        )
        # Stash the user record on the request for downstream middleware / handlers.
        request.scope["sso_user"] = user
        return resp

    app.get(f"{prefix}/login/{{provider}}")(_login)
    app.get(f"{prefix}/callback/{{provider}}")(_callback)


__all__ = ["OAuthUser", "attach_routes"]
