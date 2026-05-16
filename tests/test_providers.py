"""Smoke tests for GitHub / Microsoft / Discord / Facebook / LinkedIn providers."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from hawkapi_sso import (
    DiscordProvider,
    FacebookProvider,
    GitHubProvider,
    LinkedInProvider,
    MicrosoftProvider,
    OAuthError,
)

from .conftest import attach_mock_transport


def _multi_handler(routes: dict[str, dict[str, Any]]):
    def handle(request: httpx.Request) -> httpx.Response:
        for key, spec in routes.items():
            if key in str(request.url):
                return httpx.Response(spec.get("status", 200), json=spec.get("json"))
        return httpx.Response(404)

    return handle


# --------------------------------------------------------------------------- #
# GitHub                                                                      #
# --------------------------------------------------------------------------- #


async def test_github_userinfo_with_primary_email(github: GitHubProvider) -> None:
    attach_mock_transport(
        github,
        _multi_handler(
            {
                "/login/oauth/access_token": {"json": {"access_token": "AT"}},
                "/user/emails": {
                    "json": [
                        {"email": "a@b.c", "primary": True, "verified": True},
                        {"email": "other@b.c", "primary": False, "verified": False},
                    ]
                },
                "/user": {"json": {"id": 42, "login": "alice", "avatar_url": "u"}},
            }
        ),
    )
    token = await github.exchange_code("c", redirect_uri="https://app.example/cb")
    user = await github.fetch_userinfo(token)
    assert user.provider == "github"
    assert user.sub == "42"
    assert user.email == "a@b.c"
    assert user.email_verified is True


async def test_github_unverified_email_flagged_false(github: GitHubProvider) -> None:
    attach_mock_transport(
        github,
        _multi_handler(
            {
                "/login/oauth/access_token": {"json": {"access_token": "AT"}},
                "/user/emails": {"json": [{"email": "x@y.z", "primary": True, "verified": False}]},
                "/user": {"json": {"id": 1, "login": "x"}},
            }
        ),
    )
    token = await github.exchange_code("c", redirect_uri="https://app.example/cb")
    user = await github.fetch_userinfo(token)
    assert user.email == "x@y.z"
    assert user.email_verified is False


# --------------------------------------------------------------------------- #
# Microsoft                                                                   #
# --------------------------------------------------------------------------- #


def test_microsoft_endpoints_templated_by_tenant() -> None:
    p = MicrosoftProvider(client_id="c", client_secret="s", tenant="contoso.onmicrosoft.com")
    assert "contoso.onmicrosoft.com" in p.authorization_url
    assert "contoso.onmicrosoft.com" in p.token_url


async def test_microsoft_userinfo_happy_path(microsoft: MicrosoftProvider) -> None:
    attach_mock_transport(
        microsoft,
        _multi_handler(
            {
                "/oauth2/v2.0/token": {"json": {"access_token": "AT"}},
                "userinfo": {
                    "json": {
                        "sub": "ms-1",
                        "email": "a@contoso.com",
                        "email_verified": True,
                        "name": "Alice",
                    }
                },
            }
        ),
    )
    token = await microsoft.exchange_code("c", redirect_uri="https://app.example/cb")
    user = await microsoft.fetch_userinfo(token)
    assert user.sub == "ms-1"
    assert user.email == "a@contoso.com"


# --------------------------------------------------------------------------- #
# Discord                                                                     #
# --------------------------------------------------------------------------- #


async def test_discord_userinfo_with_avatar(discord: DiscordProvider) -> None:
    attach_mock_transport(
        discord,
        _multi_handler(
            {
                "/oauth2/token": {"json": {"access_token": "AT"}},
                "/users/@me": {
                    "json": {
                        "id": "777",
                        "username": "alice",
                        "global_name": "Alice",
                        "email": "a@b.c",
                        "verified": True,
                        "avatar": "abc",
                    }
                },
            }
        ),
    )
    token = await discord.exchange_code("c", redirect_uri="https://app.example/cb")
    user = await discord.fetch_userinfo(token)
    assert user.sub == "777"
    assert user.email_verified is True
    assert "avatars/777/abc.png" in user.picture


# --------------------------------------------------------------------------- #
# Facebook                                                                    #
# --------------------------------------------------------------------------- #


async def test_facebook_userinfo_default_email_verified_false(facebook: FacebookProvider) -> None:
    attach_mock_transport(
        facebook,
        _multi_handler(
            {
                "/oauth/access_token": {"json": {"access_token": "AT"}},
                "graph.facebook.com/me": {
                    "json": {
                        "id": "fb-1",
                        "email": "a@b.c",
                        "name": "Alice",
                        "picture": {"data": {"url": "https://example/pic"}},
                    }
                },
            }
        ),
    )
    token = await facebook.exchange_code("c", redirect_uri="https://app.example/cb")
    user = await facebook.fetch_userinfo(token)
    assert user.sub == "fb-1"
    assert user.email == "a@b.c"
    # Facebook does not assert verification; we default to False.
    assert user.email_verified is False
    assert user.picture == "https://example/pic"


# --------------------------------------------------------------------------- #
# LinkedIn                                                                    #
# --------------------------------------------------------------------------- #


async def test_linkedin_userinfo(linkedin: LinkedInProvider) -> None:
    attach_mock_transport(
        linkedin,
        _multi_handler(
            {
                "/accessToken": {"json": {"access_token": "AT"}},
                "userinfo": {
                    "json": {
                        "sub": "li-1",
                        "email": "alice@li.example",
                        "email_verified": True,
                        "name": "Alice",
                    }
                },
            }
        ),
    )
    token = await linkedin.exchange_code("c", redirect_uri="https://app.example/cb")
    user = await linkedin.fetch_userinfo(token)
    assert user.sub == "li-1"
    assert user.email_verified is True


# --------------------------------------------------------------------------- #
# Cross-provider error paths                                                  #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "fixture",
    ["github", "microsoft", "discord", "facebook", "linkedin"],
)
async def test_userinfo_500_raises_oautherror(fixture: str, request: Any) -> None:
    provider = request.getfixturevalue(fixture)

    def handle(req: httpx.Request) -> httpx.Response:
        # Token exchange succeeds; userinfo fails.
        if "token" in str(req.url) or "accessToken" in str(req.url):
            return httpx.Response(200, json={"access_token": "AT"})
        return httpx.Response(500)

    attach_mock_transport(provider, handle)
    token = await provider.exchange_code("c", redirect_uri="https://app.example/cb")
    with pytest.raises(OAuthError):
        await provider.fetch_userinfo(token)
