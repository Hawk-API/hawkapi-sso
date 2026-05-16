"""Google provider — token exchange + userinfo via MockTransport."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from hawkapi_sso import GoogleProvider, OAuthError

from .conftest import attach_mock_transport


def _handler(token_body: Any, info_body: Any, *, token_status: int = 200, info_status: int = 200):
    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/token"):
            return httpx.Response(
                token_status,
                json=token_body if isinstance(token_body, dict) else None,
                content=None if isinstance(token_body, dict) else token_body,
            )
        if "userinfo" in request.url.path:
            return httpx.Response(
                info_status,
                json=info_body if isinstance(info_body, dict) else None,
                content=None if isinstance(info_body, dict) else info_body,
            )
        return httpx.Response(404)

    return handle


def test_authorize_url_contains_pkce(google: GoogleProvider) -> None:
    url = google.build_authorize_url(
        redirect_uri="https://app.example/cb",
        state="s1",
        code_challenge="c1",
    )
    assert "response_type=code" in url
    assert "client_id=test-client" in url
    assert "code_challenge=c1" in url
    assert "code_challenge_method=S256" in url


async def test_exchange_code_success(google: GoogleProvider) -> None:
    attach_mock_transport(
        google,
        _handler(
            {"access_token": "AT", "token_type": "Bearer", "expires_in": 3600, "id_token": "ID"},
            {"sub": "u-1", "email": "a@b.c", "email_verified": True, "name": "A"},
        ),
    )
    token = await google.exchange_code(
        "code", redirect_uri="https://app.example/cb", code_verifier="v"
    )
    assert token.access_token == "AT"
    assert token.id_token == "ID"
    user = await google.fetch_userinfo(token)
    assert user.provider == "google"
    assert user.sub == "u-1"
    assert user.email == "a@b.c"
    assert user.email_verified is True


async def test_exchange_code_failure_raises(google: GoogleProvider) -> None:
    attach_mock_transport(google, _handler({"error": "bad"}, {}, token_status=400))
    with pytest.raises(OAuthError, match="token exchange failed"):
        await google.exchange_code("code", redirect_uri="https://app.example/cb")


async def test_userinfo_missing_sub_rejected(google: GoogleProvider) -> None:
    attach_mock_transport(google, _handler({"access_token": "AT"}, {"email": "a@b.c"}))
    token = await google.exchange_code("code", redirect_uri="https://app.example/cb")
    with pytest.raises(OAuthError, match="missing sub"):
        await google.fetch_userinfo(token)


async def test_userinfo_http_error_raises(google: GoogleProvider) -> None:
    attach_mock_transport(google, _handler({"access_token": "AT"}, {}, info_status=500))
    token = await google.exchange_code("code", redirect_uri="https://app.example/cb")
    with pytest.raises(OAuthError, match="userinfo failed"):
        await google.fetch_userinfo(token)


async def test_token_response_missing_access_token_rejected(google: GoogleProvider) -> None:
    attach_mock_transport(google, _handler({"token_type": "Bearer"}, {}))
    with pytest.raises(OAuthError, match="missing access_token"):
        await google.exchange_code("code", redirect_uri="https://app.example/cb")
