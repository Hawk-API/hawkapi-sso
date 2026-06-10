"""HMAC-signed state cookie."""

from __future__ import annotations

import time

import pytest

from hawkapi_sso import StatePayload, new_nonce, sign_state, verify_state

SECRET = "test-state-secret-32-chars-or-more!"


def test_roundtrip() -> None:
    p = StatePayload(
        nonce="abc",
        provider="google",
        redirect_uri="https://app.example/cb",
        next_url="/me",
        code_verifier="v",
    )
    signed = sign_state(p, secret=SECRET)
    out = verify_state(signed, secret=SECRET)
    assert out.nonce == "abc"
    assert out.provider == "google"
    assert out.redirect_uri == "https://app.example/cb"
    assert out.next_url == "/me"
    # The PKCE verifier must NOT leak into the URL-bound state token.
    assert out.code_verifier == ""


def test_code_verifier_only_in_cookie_variant() -> None:
    """``code_verifier`` is serialized only when ``include_verifier=True`` (cookie)."""
    p = StatePayload(nonce="abc", provider="google", redirect_uri="x", code_verifier="v")
    url_token = sign_state(p, secret=SECRET)
    cookie_token = sign_state(p, secret=SECRET, include_verifier=True)
    assert verify_state(url_token, secret=SECRET).code_verifier == ""
    assert verify_state(cookie_token, secret=SECRET).code_verifier == "v"
    # And the verifier value must not appear anywhere in the URL token's bytes.
    import base64

    body_b64 = url_token.split(".", 1)[0]
    padded = body_b64 + "=" * (-len(body_b64) % 4)
    assert b"code_verifier" not in base64.urlsafe_b64decode(padded)


def test_tampered_signature_rejected() -> None:
    p = StatePayload(nonce="abc", provider="google", redirect_uri="x", next_url="/")
    signed = sign_state(p, secret=SECRET)
    body, _sig = signed.rsplit(".", 1)
    bad = body + "." + ("A" * 43)
    with pytest.raises(ValueError, match="signature"):
        verify_state(bad, secret=SECRET)


def test_different_secret_rejected() -> None:
    p = StatePayload(nonce="abc", provider="google", redirect_uri="x", next_url="/")
    signed = sign_state(p, secret=SECRET)
    with pytest.raises(ValueError, match="signature"):
        verify_state(signed, secret="other-secret-with-32-chars-or-mor")


def test_expired_token_rejected() -> None:
    past = int(time.time()) - 3600
    p = StatePayload(nonce="abc", provider="google", redirect_uri="x", next_url="/", iat=past)
    signed = sign_state(p, secret=SECRET)
    with pytest.raises(ValueError, match="expired"):
        verify_state(signed, secret=SECRET, ttl=60)


def test_malformed_state_rejected() -> None:
    with pytest.raises(ValueError, match="malformed"):
        verify_state("not-a-token", secret=SECRET)


def test_new_nonce_unique() -> None:
    assert new_nonce() != new_nonce()


def test_sign_requires_secret() -> None:
    p = StatePayload(nonce="a", provider="g", redirect_uri="x")
    with pytest.raises(ValueError, match="secret"):
        sign_state(p, secret="")


def test_verify_requires_secret() -> None:
    with pytest.raises(ValueError, match="secret"):
        verify_state("any", secret="")
