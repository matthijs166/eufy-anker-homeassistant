"""End-to-end login tests against an in-process fake of the Eufy cloud."""
from __future__ import annotations

import base64
import hashlib
import hmac
import importlib
import json
import os
import sys
import types
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Load the modules without running the package __init__ (needs Home Assistant).
_PKG_DIR = Path(__file__).parent.parent / "custom_components" / "eufy_anker_ha"
_pkg = types.ModuleType("eufy_anker_ha")
_pkg.__path__ = [str(_PKG_DIR)]
sys.modules["eufy_anker_ha"] = _pkg
api_mod = importlib.import_module("eufy_anker_ha.api")
crypto = importlib.import_module("eufy_anker_ha.crypto")


def _pub_hex(key):
    return key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    ).hex()


class FakeCloud:
    """Plays the gateway: key exchange, signature check, login, captcha, 2FA."""

    def __init__(self, require_captcha=False, require_2fa=False):
        self.static = ec.generate_private_key(ec.SECP256R1())
        self.keys: dict[str, str] = {}
        self.require_captcha = require_captcha
        self.require_2fa = require_2fa
        self.calls: list[str] = []

    def _decrypt_pw(self, client_pub: str, b64: str) -> str:
        shared = self.static.exchange(
            ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(client_pub))
        )
        return crypto._aes_cbc_decrypt(shared, shared[:16], base64.b64decode(b64)).decode()

    async def post(self, url, body, headers):
        host, path = url[len("https://"):].split("/", 1)
        path = "/" + path
        self.calls.append(f"{host}{path}")
        if path.endswith("/passport/estimate_domain"):
            return 200, {"code": 0, "data": {"domain": "app-openapi-eu-pr.eufy.com"}}
        if path.endswith("/key/exchange"):
            local_hex = crypto.EUFYLIFE_LOCAL_KEY_HEX if "eufylife" in host else crypto.MEGA_LOCAL_KEY_HEX
            enc_pub = json.loads(body)["client_public_key"]
            ts, once = headers["x-request-ts"], headers["x-request-once"]
            assert headers["x-signature"] == hmac.new(
                local_hex.encode(), f"{ts}+{once}+{enc_pub}".encode(), hashlib.sha256
            ).hexdigest()
            blob = base64.b64decode(enc_pub)
            local = bytes.fromhex(local_hex)
            client_hex = crypto._aes_cbc_decrypt(local, blob[:16], blob[16:]).decode()
            srv = ec.generate_private_key(ec.SECP256R1())
            shared = srv.exchange(
                ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(client_hex))
            )
            self.keys[headers["x-key-ident"]] = shared.hex().rjust(64, "0")[:32]
            iv = os.urandom(16)
            wrapped = base64.b64encode(iv + crypto._aes_cbc_encrypt(local, iv, _pub_hex(srv).encode())).decode()
            return 200, {"code": 0, "data": {"server_public_key": wrapped}}
        share = self.keys[headers["x-key-ident"]]
        assert headers["x-signature"] == crypto.sign_request(
            share, headers["x-request-ts"], headers["x-request-once"], body
        )
        req = json.loads(crypto.decrypt_body(body, share))
        return 200, self._handle(path, req, headers, share)

    def _ok(self, data, share):
        return {"code": 0, "msg": "ok", "data": crypto.encrypt_body(json.dumps(data), share)}

    def _handle(self, path, req, headers, share):
        if path == "/passport/login":
            if self.require_captcha and req.get("answer") != "1234":
                return {"code": 100032, "msg": "captcha"}
            assert self._decrypt_pw(req["client_secret_info"]["public_key"], req["password"]) == "s3cret"
            if self.require_2fa and req.get("verify_code") != "999":
                return self._ok(
                    {"ap_cloud_user_id": "u1", "user_id": "u1", "auth_token": "limited", "fa_info": {"info": "x"}},
                    share,
                )
            if self.require_2fa:
                assert headers["x-auth-token"] == "limited"
            return self._ok(
                {"ap_cloud_user_id": "u1", "user_id": "u1", "auth_token": "tok", "token_expires_at": 1}, share
            )
        if path == "/passport/generate/captcha":
            return self._ok({"captcha_id": "cap1", "item": "data:image/png;base64,AAAA"}, share)
        if path == "/app/sendmsg/verify_code":
            assert headers["x-auth-token"] == "limited"
            return self._ok({}, share)
        assert headers["x-auth-token"] == "tok"
        if path == "/app/house/get_house_list":
            return self._ok({"house_infos": []}, share)
        if path == "/app/house/get_devs_list":
            return self._ok(
                {"devices": [{"device_sn": "T1", "params": [{"param_type": 99904, "param_value": "1"}]}]}, share
            )
        return {"code": 1, "msg": "unknown"}


def _make(cloud, monkeypatch):
    monkeypatch.setattr(crypto, "SERVER_STATIC_PUBLIC_KEY_HEX", _pub_hex(cloud.static))
    api = api_mod.EufyApi(None, "me@example.com", "s3cret", country="NL")
    monkeypatch.setattr(api, "_http_post", lambda url, body, headers: cloud.post(url, body, headers))
    return api


def test_retry_after_seconds_reads_duration_from_server_message():
    assert api_mod._retry_after_seconds({}, "Please try again in 2 minutes") == 120
    assert api_mod._retry_after_seconds({}, "retry after 30 seconds") == 30
    assert api_mod._retry_after_seconds({}, "wait 1 hour") == 3600


def test_retry_after_seconds_prefers_header_and_handles_unknown_duration():
    assert api_mod._retry_after_seconds({"retry-after": "90"}, "retry in 2 minutes") == 90
    assert api_mod._retry_after_seconds({}, "Too many login attempts") is None


@pytest.mark.asyncio
async def test_plain_login_and_devices(monkeypatch):
    cloud = FakeCloud()
    api = _make(cloud, monkeypatch)
    await api.login()
    assert api.auth["token"] == "tok" and api.auth["region"] == "eu-pr"
    devs = await api.get_cameras()
    assert [d["device_sn"] for d in devs] == ["T1"]
    assert api_mod.privacy_enabled(devs[0])
    assert any(c.startswith("app-passport-eu-pr.eufy.com/passport/login") for c in cloud.calls)


@pytest.mark.asyncio
async def test_captcha_flow(monkeypatch):
    cloud = FakeCloud(require_captcha=True)
    api = _make(cloud, monkeypatch)
    with pytest.raises(api_mod.EufyCaptchaRequired) as exc:
        await api.login()
    assert exc.value.captcha_id == "cap1"
    await api.login(captcha_id="cap1", captcha_answer="1234")
    assert api.auth["token"] == "tok"


@pytest.mark.asyncio
async def test_two_factor_flow(monkeypatch):
    cloud = FakeCloud(require_2fa=True)
    api = _make(cloud, monkeypatch)
    with pytest.raises(api_mod.EufyTwoFactorRequired):
        await api.login()
    await api.login(verify_code="999")
    assert api.auth["token"] == "tok"


@pytest.mark.asyncio
async def test_set_privacy_uses_fresh_6250_param_when_device_list_omits_it(monkeypatch):
    api = api_mod.EufyApi(None, "me@example.com", "s3cret")
    submitted = []

    async def get_device_params(device_sn):
        assert device_sn == "T1"
        return [{"param_type": 6250, "param_value": "0"}]

    async def authed(host_kind, path, body, service=""):
        submitted.append(body)
        return {"result": "ok"}

    monkeypatch.setattr(api, "get_device_params", get_device_params)
    monkeypatch.setattr(api, "_authed", authed)

    await api.set_privacy(
        {"device_sn": "T1", "params": [{"param_type": 99904, "param_value": "0"}]},
        True,
    )

    assert [param["param_type"] for param in submitted[0]["params"]] == [99904, 6250]
    assert all(param["param_value"] == "1" for param in submitted[0]["params"])
