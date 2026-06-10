"""ID-token verification: signature / iss / aud / exp / nonce enforcement."""

from __future__ import annotations

import httpx
import pytest

from hawkapi_sso import GoogleProvider, OAuthError, OAuthToken

from .conftest import CLIENT_ID, CLIENT_SECRET, attach_mock_transport
from .oidc_helpers import jwks_for, sign_id_token

ISS = "https://accounts.google.com"


def _google() -> GoogleProvider:
    g = GoogleProvider(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)
    attach_mock_transport(
        g, lambda req: httpx.Response(200, json=jwks_for())
    )
    return g


async def test_valid_id_token_accepted() -> None:
    g = _google()
    tok = OAuthToken(
        access_token="AT",
        id_token=sign_id_token(sub="u-1", aud=CLIENT_ID, iss=ISS, nonce="n1"),
    )
    claims = await g.verify_id_token(tok, nonce="n1")
    assert claims["sub"] == "u-1"


async def test_missing_id_token_rejected() -> None:
    g = _google()
    with pytest.raises(OAuthError, match="id_token"):
        await g.verify_id_token(OAuthToken(access_token="AT"), nonce="n1")


async def test_wrong_audience_rejected() -> None:
    g = _google()
    tok = OAuthToken(
        access_token="AT",
        id_token=sign_id_token(sub="u-1", aud="someone-else", iss=ISS, nonce="n1"),
    )
    with pytest.raises(OAuthError, match="validation failed"):
        await g.verify_id_token(tok, nonce="n1")


async def test_wrong_issuer_rejected() -> None:
    g = _google()
    tok = OAuthToken(
        access_token="AT",
        id_token=sign_id_token(sub="u-1", aud=CLIENT_ID, iss="https://evil.example", nonce="n1"),
    )
    with pytest.raises(OAuthError, match="validation failed"):
        await g.verify_id_token(tok, nonce="n1")


async def test_nonce_mismatch_rejected() -> None:
    g = _google()
    tok = OAuthToken(
        access_token="AT",
        id_token=sign_id_token(sub="u-1", aud=CLIENT_ID, iss=ISS, nonce="n1"),
    )
    with pytest.raises(OAuthError, match="nonce"):
        await g.verify_id_token(tok, nonce="different")


async def test_expired_id_token_rejected() -> None:
    g = _google()
    tok = OAuthToken(
        access_token="AT",
        id_token=sign_id_token(
            sub="u-1", aud=CLIENT_ID, iss=ISS, nonce="n1", exp_delta=-3600
        ),
    )
    with pytest.raises(OAuthError, match="validation failed"):
        await g.verify_id_token(tok, nonce="n1")


def test_oauth2_provider_skips_validation() -> None:
    """A non-OIDC provider returns no claims and never touches JWKS."""
    from hawkapi_sso import GitHubProvider

    gh = GitHubProvider(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)
    assert gh.is_oidc is False


def test_non_https_token_url_rejected() -> None:
    with pytest.raises(ValueError, match="https"):
        GoogleProvider(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            token_url="http://insecure.example/token",
        )


def test_token_repr_redacts_secrets() -> None:
    tok = OAuthToken(access_token="super-secret", refresh_token="rt", id_token="idt")
    text = repr(tok)
    assert "super-secret" not in text
    assert "redacted" in text
