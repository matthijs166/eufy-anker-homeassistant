"""Minimal async client for the Eufy (Anker) security cloud.

Inspired by https://github.com/mega-yfue/eufy-sdk. The protocol is
reverse engineered and may change without notice.
"""
from __future__ import annotations

import base64
import hashlib
import time
import uuid
from typing import Any

from aiohttp import ClientSession
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

API_BASE = "https://security-app.eufylife.com"
PARAM_PRIVACY_MODE = 99904

CODE_OK = 0
CODE_CAPTCHA = 100033
CODE_NEED_VERIFY = 26052
CODE_BAD_PASSWORD = 26006


class EufyError(Exception):
    """Base error."""


class EufyAuthError(EufyError):
    """Invalid credentials or verification code."""


class EufyCaptchaRequired(EufyError):
    """A captcha must be answered."""

    def __init__(self, captcha_id: str, image: str) -> None:
        super().__init__("captcha required")
        self.captcha_id = captcha_id
        self.image = image


class EufyTwoFactorRequired(EufyError):
    """A 2FA verification code was sent to the user."""


class EufyApi:
    """Eufy cloud client."""

    def __init__(
        self,
        session: ClientSession,
        email: str,
        password: str,
        auth: dict[str, Any] | None = None,
    ) -> None:
        self._session = session
        self._email = email
        self._password = password
        self._auth = auth or {}
        self._openudid = self._auth.get("openudid") or uuid.uuid4().hex[:16]
        self._key = ec.generate_private_key(ec.SECP256R1())
        self._base = self._auth.get("domain") or API_BASE

    @property
    def auth(self) -> dict[str, Any]:
        """Return serialisable auth state for storing in the config entry."""
        return {**self._auth, "openudid": self._openudid}

    def _headers(self) -> dict[str, str]:
        headers = {
            "app_version": "v4.6.0_1630",
            "os_type": "android",
            "os_version": "31",
            "phone_model": "ONEPLUS A3003",
            "country": "US",
            "language": "en",
            "openudid": self._openudid,
            "uid": self._auth.get("user_id", ""),
            "net_type": "wifi",
            "mnc": "02",
            "mcc": "262",
            "sn": hashlib.md5(self._openudid.encode()).hexdigest()[:12],
            "Model_type": "PHONE",
            "timezone": "Europe/Amsterdam",
            "Content-Type": "application/json",
        }
        if self._auth.get("token"):
            headers["X-Auth-Token"] = self._auth["token"]
        return headers

    def _encrypt_password(self, server_public_hex: str) -> str:
        server_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), bytes.fromhex(server_public_hex)
        )
        secret = self._key.exchange(ec.ECDH(), server_key)
        padder = padding.PKCS7(128).padder()
        data = padder.update(self._password.encode()) + padder.finalize()
        enc = Cipher(algorithms.AES(secret), modes.CBC(secret[:16])).encryptor()
        return base64.b64encode(enc.update(data) + enc.finalize()).decode()

    def _public_hex(self) -> str:
        return self._key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        ).hex()

    async def _post(self, path: str, body: dict[str, Any], base: str | None = None) -> dict:
        async with self._session.post(
            f"{base or self._base}{path}", json=body, headers=self._headers()
        ) as resp:
            return await resp.json(content_type=None)

    async def login(
        self,
        captcha_id: str | None = None,
        captcha_answer: str | None = None,
        verify_code: str | None = None,
    ) -> None:
        """Log in. Raises captcha / 2FA exceptions when more input is needed."""
        # First fetch the server public key by sending a login with a plain probe.
        probe = await self._post(
            "/v2/passport/login_sec",
            {
                "ab": "US",
                "client_secret_info": {"public_key": self._public_hex()},
                "enc": 0,
                "email": self._email,
                "password": "",
                "time_zone": 3600000,
                "transaction": str(int(time.time() * 1000)),
            },
        )
        server_pub = (
            (probe.get("data") or {}).get("server_secret_info", {}).get("public_key")
        )
        if not server_pub:
            raise EufyError(f"Unexpected login response: {probe.get('msg')}")
        body: dict[str, Any] = {
            "ab": "US",
            "client_secret_info": {"public_key": self._public_hex()},
            "enc": 0,
            "email": self._email,
            "password": self._encrypt_password(server_pub),
            "time_zone": 3600000,
            "transaction": str(int(time.time() * 1000)),
        }
        if captcha_id and captcha_answer:
            body["captcha_id"] = captcha_id
            body["answer"] = captcha_answer
        if verify_code:
            body["verify_code"] = verify_code
        result = await self._post("/v2/passport/login_sec", body)
        code = result.get("code")
        data = result.get("data") or {}
        if code == CODE_CAPTCHA:
            raise EufyCaptchaRequired(data.get("captcha_id", ""), data.get("item", ""))
        if code == CODE_NEED_VERIFY:
            self._auth["token"] = data.get("auth_token", "")
            await self._post(
                "/v1/sms/send/verify_code",
                {"message_type": 2, "transaction": str(int(time.time() * 1000))},
            )
            raise EufyTwoFactorRequired
        if code == CODE_BAD_PASSWORD:
            raise EufyAuthError(result.get("msg", "invalid credentials"))
        if code != CODE_OK:
            raise EufyAuthError(result.get("msg", f"login failed ({code})"))
        domain = data.get("domain")
        self._auth.update(
            token=data["auth_token"],
            user_id=data.get("user_id", ""),
            expires=data.get("token_expires_at", 0),
            domain=f"https://{domain}" if domain else API_BASE,
        )
        self._base = self._auth["domain"]

    async def _authed(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        result = await self._post(path, body)
        if result.get("code") != CODE_OK:
            await self.login()
            result = await self._post(path, body)
        if result.get("code") != CODE_OK:
            raise EufyError(result.get("msg", "request failed"))
        return result.get("data")

    async def get_cameras(self) -> list[dict[str, Any]]:
        """Return all camera devices of the account."""
        data = await self._authed("/v1/app/get_devs_list", {"device_sn": "", "num": 1000, "orderby": "", "page": 0, "station_sn": ""})
        return [d for d in data or [] if d.get("device_sn")]

    async def get_events(self) -> list[dict[str, Any]]:
        """Return recent alarm/motion events across all devices."""
        data = await self._authed(
            "/v1/event/app/get_all_alarm_record",
            {"device_sn": "", "end_time": 0, "start_time": 0, "num": 50,
             "pullup": True, "shared": True, "station_sn": ""},
        )
        return data or []

    async def get_image(self, url: str) -> bytes | None:
        """Download an image."""
        async with self._session.get(url) as resp:
            return await resp.read() if resp.status == 200 else None

    async def set_privacy(self, device: dict[str, Any], enabled: bool) -> None:
        """Turn privacy mode on or off."""
        await self._authed(
            "/v1/app/upload_devs_params",
            {
                "device_sn": device["device_sn"],
                "station_sn": device.get("station_sn", device["device_sn"]),
                "params": [{"param_type": PARAM_PRIVACY_MODE, "param_value": "1" if enabled else "0"}],
            },
        )
