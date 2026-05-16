"""Shared fixtures for hawkapi-sso tests."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from hawkapi_sso import (
    DiscordProvider,
    FacebookProvider,
    GitHubProvider,
    GoogleProvider,
    LinkedInProvider,
    MicrosoftProvider,
)

CLIENT_ID = "test-client"
CLIENT_SECRET = "test-secret"
STATE_SECRET = "a" * 32  # not a real secret; tests only


def attach_mock_transport(provider: Any, handler: Any) -> None:
    """Replace the provider's internal httpx client with a MockTransport-backed one."""
    provider._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.fixture
def google() -> GoogleProvider:
    return GoogleProvider(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)


@pytest.fixture
def github() -> GitHubProvider:
    return GitHubProvider(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)


@pytest.fixture
def microsoft() -> MicrosoftProvider:
    return MicrosoftProvider(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)


@pytest.fixture
def discord() -> DiscordProvider:
    return DiscordProvider(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)


@pytest.fixture
def facebook() -> FacebookProvider:
    return FacebookProvider(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)


@pytest.fixture
def linkedin() -> LinkedInProvider:
    return LinkedInProvider(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)
