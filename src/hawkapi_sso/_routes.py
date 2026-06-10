"""Login + callback handlers wired by :func:`init_sso`."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from hawkapi import HTTPException, Request
from hawkapi.responses import RedirectResponse

from ._base import OAuthUser, make_pkce
from ._state import StatePayload, new_nonce, sign_state, verify_state

_log = logging.getLogger("hawkapi_sso")


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


def _failure_redirect(cfg: Any) -> RedirectResponse:
    """Redirect to the configured failure URL, clearing the state cookie."""
    resp = RedirectResponse(cfg.failure_redirect, status_code=302)
    _clear_cookie(
        resp,
        name=cfg.cookie_name,
        secure=cfg.cookie_secure,
        samesite=cfg.cookie_samesite,
    )
    return resp


def _read_cookie(request: Request, name: str) -> str:
    raw = request.headers.get("cookie", "") if hasattr(request, "headers") else ""
    if not raw:
        return ""
    for chunk in raw.split(";"):
        k, _, v = chunk.strip().partition("=")
        if k == name:
            return v
    return ""


def _is_safe_next(next_url: Any) -> bool:
    """True if ``next_url`` is a same-site, path-only redirect target."""
    if not isinstance(next_url, str) or not next_url:
        return False
    # Backslashes are normalized to ``/`` by some browsers — treat them as such.
    candidate = next_url.replace("\\", "/")
    if not candidate.startswith("/") or candidate.startswith("//"):
        return False
    parsed = urlparse(candidate)
    # Reject any absolute URL: a scheme or a netloc means off-site.
    return not parsed.scheme and not parsed.netloc


def _resolve_redirect_uri(
    cfg: Any, provider: Any, provider_name: str, request: Request, prefix: str
) -> str:
    """Build the callback ``redirect_uri``, preferring a pinned value.

    Resolution order: ``provider._redirect_uri`` → ``cfg.base_url`` → Host header.
    A Host-derived URI is only allowed when the Host is in ``cfg.allowed_hosts``
    (CWE-601 / SSRF); otherwise we raise rather than trust an attacker-set Host.
    """
    pinned = getattr(provider, "_redirect_uri", "")
    if pinned:
        return pinned
    if cfg.base_url:
        return f"{cfg.base_url}{prefix}/callback/{provider_name}"

    raw_url = getattr(request, "url", "")
    scheme = urlparse(str(raw_url)).scheme or "https"
    host = request.headers.get("host", "")
    if cfg.allowed_hosts:
        if host not in cfg.allowed_hosts:
            raise HTTPException(400, detail="invalid request host")
    else:
        _log.warning(
            "hawkapi-sso: redirect_uri derived from unvalidated Host header %r; "
            "pin provider._redirect_uri or set SSOConfig.base_url/allowed_hosts.",
            host,
        )
    return f"{scheme}://{host}{prefix}/callback/{provider_name}"


def attach_routes(app: Any, cfg: Any) -> None:
    """Register ``/login/{provider}`` and ``/callback/{provider}`` on ``app``."""
    prefix = cfg.login_path_prefix

    async def _login(request: Request) -> Any:
        provider_name = str(request.path_params["provider"])
        provider = _provider_or_404(cfg, provider_name)
        # next_url is the in-app URL we redirect to on success — never a full URL.
        # Reject anything with a scheme or netloc (``//host``, ``https:`` …) and
        # normalize backslashes, which some browsers treat as ``/`` (CWE-601).
        next_param = request.query_params.get("next", cfg.success_redirect)
        next_url: str = (
            next_param
            if isinstance(next_param, str) and _is_safe_next(next_param)
            else cfg.success_redirect
        )

        # PKCE — only meaningful where the provider supports it.
        verifier = ""
        challenge = ""
        if provider.supports_pkce:
            verifier, challenge = make_pkce()

        # OIDC nonce binds the id_token to this login. Reuse the state nonce.
        nonce = new_nonce()

        redirect_uri = _resolve_redirect_uri(cfg, provider, provider_name, request, prefix)

        payload = StatePayload(
            nonce=nonce,
            provider=provider_name,
            redirect_uri=redirect_uri,
            next_url=next_url,
            code_verifier=verifier,
        )
        # URL state: NO code_verifier (it would leak to the provider).
        url_state = sign_state(payload, secret=cfg.state_secret)
        # Cookie state: carries the verifier; never sent to the auth server.
        cookie_state = sign_state(payload, secret=cfg.state_secret, include_verifier=True)
        url = provider.build_authorize_url(
            redirect_uri=redirect_uri,
            state=url_state,
            code_challenge=challenge,
            nonce=nonce,
        )
        return _redirect_with_cookie(
            url,
            name=cfg.cookie_name,
            value=cookie_state,
            attrs=_cookie_attrs(cfg),
        )

    async def _callback(request: Request) -> Any:
        provider_name = str(request.path_params["provider"])
        provider = _provider_or_404(cfg, provider_name)
        state_q = request.query_params.get("state", "")
        state_c = _read_cookie(request, cfg.cookie_name)
        code = request.query_params.get("code", "")
        error = request.query_params.get("error", "")

        # The provider may abort the flow (user denied consent, invalid_scope, …).
        # Honour it: clear the state cookie and bounce to the failure redirect
        # instead of returning a misleading 400.
        if error:
            _log.info("hawkapi-sso: provider %s returned error %r", provider_name, error)
            return _failure_redirect(cfg)

        # CSRF: the URL ``state`` and the cookie state are signed from the same
        # payload but differ in one field (the cookie carries the PKCE verifier),
        # so they can't be compared byte-for-byte. Validate both and require the
        # nonces to match.
        if not code or not state_q or not state_c:
            raise HTTPException(400, detail="invalid state")

        try:
            url_payload = verify_state(state_q, secret=cfg.state_secret, ttl=cfg.state_ttl_seconds)
            payload = verify_state(state_c, secret=cfg.state_secret, ttl=cfg.state_ttl_seconds)
        except ValueError as exc:
            # Don't leak the internal validation reason to the client.
            _log.warning("hawkapi-sso: state validation failed: %s", exc)
            raise HTTPException(400, detail="invalid state") from exc

        if (
            not url_payload.nonce
            or url_payload.nonce != payload.nonce
            or payload.provider != provider_name
            or url_payload.provider != provider_name
        ):
            raise HTTPException(400, detail="invalid state")

        token = await provider.exchange_code(
            code,
            redirect_uri=payload.redirect_uri,
            code_verifier=payload.code_verifier,
        )
        # OIDC: verify the id_token (signature + iss/aud/exp/nonce) and use its
        # validated ``sub`` as the authoritative identity. No-op for OAuth2-only
        # providers (GitHub/Facebook/Discord).
        if getattr(provider, "is_oidc", False):
            claims = await provider.verify_id_token(token, nonce=payload.nonce)
            user = await provider.fetch_userinfo(token)
            authoritative_sub = str(claims.get("sub", ""))
            if authoritative_sub and user.sub != authoritative_sub:
                _log.warning(
                    "hawkapi-sso: %s userinfo sub %r != id_token sub %r; using id_token",
                    provider_name,
                    user.sub,
                    authoritative_sub,
                )
                user.sub = authoritative_sub
        else:
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
