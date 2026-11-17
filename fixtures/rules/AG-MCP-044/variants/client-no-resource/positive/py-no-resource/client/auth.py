import base64
import hashlib
import secrets
from urllib.parse import urlencode

import httpx


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def authorization_url(metadata: dict, client_id: str, redirect_uri: str, server_url: str, challenge: str, state: str) -> str:
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    return f"{metadata['authorization_endpoint']}?{urlencode(params)}"


def redeem(metadata: dict, client_id: str, redirect_uri: str, server_url: str, code: str, verifier: str) -> dict:
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": verifier,
    }
    return httpx.post(metadata["token_endpoint"], data=form, timeout=10).json()
