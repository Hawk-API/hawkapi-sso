"""End-to-end test: /login/{provider} → state cookie → /callback/{provider}."""

from __future__ import annotations

import httpx
from hawkapi import HawkAPI
from hawkapi.testing import TestClient

from hawkapi_sso import GoogleProvider, init_sso

from .conftest import CLIENT_ID, CLIENT_SECRET, STATE_SECRET, attach_mock_transport


def _build_app() -> tuple[HawkAPI, GoogleProvider]:
    app = HawkAPI(openapi_url=None, docs_url=None, redoc_url=None, scalar_url=None)
    google = GoogleProvider(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)
    init_sso(
        app,
        providers={"google": google},
        state_secret=STATE_SECRET,
        cookie_secure=False,  # TestClient does not use TLS
    )
    return app, google


def test_login_redirects_to_provider_and_sets_state_cookie() -> None:
    app, _ = _build_app()
    client = TestClient(app)
    r = client.get("/auth/sso/login/google")
    assert r.status_code == 302
    location = r.headers["location"]
    assert location.startswith("https://accounts.google.com/")
    cookie = r.headers.get("set-cookie", "")
    assert "hawkapi_sso_state=" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


def test_login_unknown_provider_404() -> None:
    app, _ = _build_app()
    r = TestClient(app).get("/auth/sso/login/bogus")
    assert r.status_code == 404


def test_callback_rejects_missing_state() -> None:
    app, _ = _build_app()
    r = TestClient(app).get("/auth/sso/callback/google?code=xyz")
    assert r.status_code == 400


def test_callback_rejects_mismatched_state() -> None:
    app, _ = _build_app()
    client = TestClient(app)
    # Get a real cookie first.
    client.get("/auth/sso/login/google")
    # Now hit callback with a forged state that differs from the cookie value.
    r = client.get("/auth/sso/callback/google?code=xyz&state=forged")
    assert r.status_code == 400


def test_protocol_relative_next_rejected() -> None:
    """Regression: ``?next=//attacker.com/x`` must NOT survive into the signed state."""
    app, _ = _build_app()
    client = TestClient(app)
    r = client.get("/auth/sso/login/google?next=//attacker.com/path")
    assert r.status_code == 302
    cookie = r.headers["set-cookie"]
    token = cookie.split("hawkapi_sso_state=", 1)[1].split(";", 1)[0]
    from hawkapi_sso import verify_state

    payload = verify_state(token, secret=STATE_SECRET)
    assert payload.next_url == "/", f"open-redirect bypass: next_url={payload.next_url!r}"


def test_callback_rejects_state_with_wrong_provider() -> None:
    """Regression: state token issued for one provider must not be accepted by another."""
    from hawkapi_sso import StatePayload, new_nonce, sign_state

    app, _ = _build_app()
    forged = sign_state(
        StatePayload(
            nonce=new_nonce(),
            provider="github",
            redirect_uri="http://testserver/cb",
            next_url="/",
        ),
        secret=STATE_SECRET,
    )
    r = TestClient(app).get(
        f"/auth/sso/callback/google?code=xyz&state={forged}",
        headers={"cookie": f"hawkapi_sso_state={forged}"},
    )
    assert r.status_code == 400


def test_init_sso_rejects_short_state_secret() -> None:
    """state_secret must be at least 32 chars (was 16)."""
    import pytest

    app = HawkAPI(openapi_url=None, docs_url=None, redoc_url=None, scalar_url=None)
    with pytest.raises(ValueError, match="32 characters"):
        init_sso(
            app,
            providers={"google": GoogleProvider(client_id="x", client_secret="y")},
            state_secret="too-short",
        )


def test_callback_provider_error_redirects_to_failure() -> None:
    """OAuth ``error`` param → clear cookie + redirect to failure_redirect (not 400)."""
    app, _ = _build_app()
    client = TestClient(app)
    client.get("/auth/sso/login/google")
    r = client.get("/auth/sso/callback/google?error=access_denied")
    assert r.status_code == 302
    assert r.headers["location"] == "/login?error=sso"
    cleared = r.headers.get("set-cookie", "")
    assert "Max-Age=0" in cleared


def test_callback_bad_state_returns_generic_detail() -> None:
    """Validation reason must not leak in the response body."""
    app, _ = _build_app()
    forged = "not.a.valid.token"
    r = TestClient(app).get(
        f"/auth/sso/callback/google?code=xyz&state={forged}",
        headers={"cookie": f"hawkapi_sso_state={forged}"},
    )
    assert r.status_code == 400
    assert "invalid state" in r.text
    assert "malformed" not in r.text


def test_backslash_next_rejected() -> None:
    """``?next=/\\attacker.com`` must not survive into the signed state."""
    app, _ = _build_app()
    client = TestClient(app)
    r = client.get("/auth/sso/login/google?next=/\\attacker.com/path")
    cookie = r.headers["set-cookie"]
    token = cookie.split("hawkapi_sso_state=", 1)[1].split(";", 1)[0]
    from hawkapi_sso import verify_state

    assert verify_state(token, secret=STATE_SECRET).next_url == "/"


def test_callback_happy_path_with_matched_state() -> None:
    app, google = _build_app()

    from .oidc_helpers import jwks_for, sign_id_token

    client = TestClient(app)
    login = client.get("/auth/sso/login/google")
    set_cookie = login.headers["set-cookie"]
    cookie_state = set_cookie.split("hawkapi_sso_state=", 1)[1].split(";", 1)[0]
    # The nonce sent to the provider is carried in the state; reuse it in the id_token.
    from hawkapi_sso import verify_state

    nonce = verify_state(cookie_state, secret=STATE_SECRET).nonce
    # The URL ``state`` is the verifier-free token embedded in the authorize URL.
    location = login.headers["location"]
    url_state = location.split("state=", 1)[1].split("&", 1)[0]
    from urllib.parse import unquote

    url_state = unquote(url_state)

    id_token = sign_id_token(
        sub="u-1",
        aud=CLIENT_ID,
        iss="https://accounts.google.com",
        nonce=nonce,
    )

    def handle(request: httpx.Request) -> httpx.Response:
        if "/oauth2/v3/certs" in request.url.path:
            return httpx.Response(200, json=jwks_for())
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "AT", "id_token": id_token})
        if "userinfo" in request.url.path:
            return httpx.Response(
                200,
                json={"sub": "u-1", "email": "a@b.c", "email_verified": True, "name": "A"},
            )
        return httpx.Response(404)

    attach_mock_transport(google, handle)

    r = client.get(
        f"/auth/sso/callback/google?code=xyz&state={url_state}",
        headers={"cookie": f"hawkapi_sso_state={cookie_state}"},
    )
    assert r.status_code == 302
    cleared = r.headers.get("set-cookie", "")
    assert "hawkapi_sso_state=" in cleared
    assert "Max-Age=0" in cleared
