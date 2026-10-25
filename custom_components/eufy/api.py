"""Async client for the Eufy (Anker) cloud.

Implements the signed/encrypted ``algo_ecdh`` transport and passport login
documented by https://github.com/mega-yfue/eufy-sdk. The protocol is reverse
engineered and may change without notice.

Login flow (``mega-client.ts`` in the SDK):
  1. ``estimate_domain`` on ``mega-{region}.eufy.com`` -> region shard.
  2. ECDH key exchange on the bootstrap host -> shareKey + X-Key-Ident that
     sign and encrypt every later call.
  3. ``/passport/login`` on ``app-passport-{region}.eufy.com``.
  4. Re-exchange the key with the auth token so it binds to the user.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from typing import Any

from aiohttp import ClientError, ClientSession

from .crypto import (
    EUFYLIFE_LOCAL_KEY_HEX,
    MEGA_LOCAL_KEY_HEX,
    decrypt_body,
    encrypt_body,
    encrypt_login_password,
    finish_key_exchange,
    gtoken,
    prepare_key_exchange,
    signed_headers,
)

_LOGGER = logging.getLogger(__name__)

APP_NAME = "eufy_mega"
APP_VERSION = "6.0.41_26142"
OS_VERSION = "36"
PHONE_MODELS = ("Pixel 8", "Pixel 7", "SM-S911B", "OnePlus 11", "Redmi Note 12")
REGIONS = ("us-pr", "eu-pr")

PARAM_PRIVACY_MODE = 99904
# Params the camera itself reacts to (cloud-only 99904 is not pushed to it)
PARAM_DEVS_SWITCH = 1035
PARAM_PRIVACY_6250 = 6250
KEY_TTL = 12 * 3600

CODE_OK = 0
CODE_IDENTITY_STALE = 4404
CODE_SIGNATURE_INVALID = 4416
CODE_PROBE_RETRY = 10000
CODE_BAD_PASSWORD = 26006
CODE_SESSION_KICKED = 26084
CODE_CAPTCHA_REQUIRED = 100032
CODE_CAPTCHA_WRONG = 100033


class EufyError(Exception):
    """Base error."""


class EufyConnectionError(EufyError):
    """Could not reach the Eufy cloud or got an unparseable response."""


class EufyAuthError(EufyError):
    """Invalid credentials or verification code."""


class EufyApiError(EufyError):
    """The cloud answered with an error envelope."""

    def __init__(self, message: str, code: int | None = None, status: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


class EufyCaptchaRequired(EufyError):
    """A captcha must be answered."""

    def __init__(self, captcha_id: str, image: str) -> None:
        super().__init__("captcha required")
        self.captcha_id = captcha_id
        self.image = image


class EufyTwoFactorRequired(EufyError):
    """A 2FA verification code was sent to the user."""


def privacy_enabled(device: dict[str, Any]) -> bool:
    """Read the privacy-mode param from a device record."""
    for param in device.get("params") or []:
        if str(param.get("param_type")) == str(PARAM_PRIVACY_MODE):
            return str(param.get("param_value")) in ("1", "True", "true")
    return False


def _looks_like_html(text: str) -> bool:
    head = text.lstrip()[:200].lower()
    return head.startswith(("<!doctype html", "<html", "<!--"))


def _proxy_error_message(url: str, status: int, text: str) -> str:
    """Describe a non-JSON (HTML) answer such as a Cloudflare/proxy error page."""
    match = re.search(r"<title>(.*?)</title>", text, re.I | re.S)
    title = " ".join(match.group(1).split()) if match else ""
    if "cloudflare" in text.lower() or "cf-error" in text:
        who = "A Cloudflare/proxy error page"
    else:
        who = "An HTML error page"
    hint = (
        " The request was likely blocked or timed out by a Cloudflare/reverse proxy in front of "
        "Home Assistant or Eufy; try again via the local Home Assistant address."
    )
    return f"{who} was returned for {url} (HTTP {status}{': ' + title if title else ''}).{hint}"


class EufyApi:
    """Eufy cloud client."""

    def __init__(
        self,
        session: ClientSession,
        email: str,
        password: str,
        auth: dict[str, Any] | None = None,
        debug: bool = False,
        country: str = "US",
    ) -> None:
        self.debug = debug
        self._session = session
        self._email = email
        self._password = password
        self._country = (country or "US").upper()
        self._auth: dict[str, Any] = dict(auth or {})
        self._openudid = self._auth.get("openudid") or hashlib.md5(
            f"eufy-mega:{email}".encode()
        ).hexdigest()[:16]
        self._phone_model = PHONE_MODELS[int(self._openudid, 16) % len(PHONE_MODELS)]
        self._region: str = self._auth.get("region") or "us-pr"
        self._bootstrap: str | None = self._auth.get("bootstrap")
        # session key of the mega host stack and per-host keys for eufylife hosts
        self._key: dict[str, Any] | None = None
        if self._auth.get("share_key") and self._auth.get("key_ident"):
            self._key = {
                "share_key": self._auth["share_key"],
                "ident": self._auth["key_ident"],
                "at": time.time(),
            }
        self._host_keys: dict[str, dict[str, Any]] = {}
        self._content_types: dict[str, str] = {}
        self._captcha_id = ""
        self._pending_2fa = False

    # -- state ------------------------------------------------------------

    @property
    def auth(self) -> dict[str, Any]:
        """Serialisable auth state for storing in the config entry."""
        out = {**self._auth, "openudid": self._openudid, "region": self._region}
        if self._bootstrap:
            out["bootstrap"] = self._bootstrap
        if self._key:
            out.update(share_key=self._key["share_key"], key_ident=self._key["ident"])
        return out

    def _base_headers(self) -> dict[str, str]:
        return {
            "app-name": APP_NAME,
            "app-version": APP_VERSION,
            "app_version": APP_VERSION,
            "os-type": "android",
            "os_type": "android",
            "os-version": OS_VERSION,
            "os_version": OS_VERSION,
            "phone-model": self._phone_model,
            "phone_model": self._phone_model,
            "model-type": "PHONE",
            "country": self._country,
            "ab_code": self._country,
            "openudid": self._openudid,
            "language": "en",
            "test-flag": "false",
            "user-agent": "ktor-client",
            "accept": "application/json",
            "accept-charset": "UTF-8",
        }

    def _token_headers(self) -> dict[str, str]:
        token = self._auth.get("token")
        if not token:
            return {}
        uid = self._auth.get("account_user_id") or self._auth.get("user_id", "")
        return {"x-auth-token": token, "authorization": token, "gtoken": gtoken(uid)}

    # -- transport --------------------------------------------------------

    async def _http_post(self, url: str, body: str, headers: dict[str, str]) -> tuple[int, Any]:
        level = logging.WARNING if self.debug else logging.DEBUG
        _LOGGER.log(level, "POST %s", url)
        try:
            async with self._session.post(url, data=body.encode(), headers=headers, timeout=20) as resp:
                text = await resp.text()
                _LOGGER.log(level, "POST %s -> HTTP %s: %s", url, resp.status, text[:300])
                try:
                    return resp.status, json.loads(text) if text else {}
                except ValueError:
                    pass
                if _looks_like_html(text) or "cf-ray" in resp.headers or "cloudflare" in resp.headers.get("server", "").lower():
                    raise EufyConnectionError(_proxy_error_message(url, resp.status, text))
                return resp.status, text
        except (ClientError, TimeoutError) as err:
            raise EufyConnectionError(
                f"Request to {url} failed: {type(err).__name__}: {err or 'no details'}"
            ) from err

    async def _estimate_domain(self) -> None:
        """Discover the region shard (step 1)."""
        last: Exception | None = None
        for region in dict.fromkeys((self._region, *REGIONS)):
            try:
                status, res = await self._http_post(
                    f"https://mega-{region}.eufy.com/passport/estimate_domain",
                    json.dumps({"ab": self._country.lower(), "mode": 1}),
                    {**self._base_headers(), "content-type": "application/json"},
                )
            except EufyConnectionError as err:
                last = err
                continue
            data = res.get("data") if isinstance(res, dict) else None
            if status != 200 or not isinstance(data, dict):
                last = EufyConnectionError(f"estimate_domain on {region} failed (HTTP {status}): {str(res)[:200]}")
                continue
            domain = str(data.get("domain") or data.get("host") or data.get("server_secret_info") or "")
            blob = json.dumps(data)
            if "-eu-" in blob or "-eu-" in domain:
                self._region = "eu-pr"
            elif "-us-" in blob or "-us-" in domain:
                self._region = "us-pr"
            else:
                self._region = region
            self._bootstrap = domain if domain and not domain.startswith("mega-") else None
            return
        raise last or EufyConnectionError("estimate_domain failed")

    async def _ensure_key(self, host: str | None = None) -> dict[str, Any]:
        """Return the session key for the mega stack or a eufylife host (step 2)."""
        lifehost = bool(host and ".eufylife.com" in host)
        cached = self._host_keys.get(host or "") if lifehost else self._key
        if cached and time.time() - cached["at"] < KEY_TTL:
            return cached
        target = host if lifehost else (self._bootstrap or f"app-openapi-{self._region}.eufy.com")
        path = "/v3/openapi/oauth/key/exchange" if lifehost else "/openapi/oauth/key/exchange"
        prep = prepare_key_exchange(EUFYLIFE_LOCAL_KEY_HEX if lifehost else MEGA_LOCAL_KEY_HEX)
        status, res = await self._http_post(
            f"https://{target}{path}",
            json.dumps(prep["body"]),
            {
                **self._base_headers(),
                **prep["headers"],
                **self._token_headers(),
                "content-type": "application/json",
            },
        )
        env = res if isinstance(res, dict) else {}
        server_pub = (env.get("data") or {}).get("server_public_key") if isinstance(env.get("data"), dict) else None
        if status != 200 or env.get("code") != CODE_OK or not server_pub:
            raise EufyApiError(
                f"key exchange on {target} failed (HTTP {status}/{env.get('code')}): "
                f"{env.get('msg') or str(res)[:160]}",
                env.get("code"),
                status,
            )
        entry = {"share_key": finish_key_exchange(prep, server_pub), "ident": prep["ident"], "at": time.time()}
        if lifehost:
            self._host_keys[host or ""] = entry
        else:
            self._key = entry
        return entry

    async def _post_signed(
        self, host: str, path: str, body: Any, authed: bool = True, _retried: bool = False
    ) -> Any:
        """Signed + encrypted POST; returns the decrypted ``data``."""
        entry = await self._ensure_key(host)
        enc_body = encrypt_body(json.dumps(body if body is not None else {}), entry["share_key"])
        cached = self._content_types.get(host)
        wants_text = "/passport/" in path or ".eufylife.com" in host
        preferred = cached or ("text/plain" if wants_text else "application/json")
        order = [preferred, "application/json" if preferred == "text/plain" else "text/plain"]
        code: int | None = None
        status = 0
        msg = ""
        for content_type in order:
            headers = {
                **self._base_headers(),
                "content-type": content_type,
                **signed_headers(entry["ident"], entry["share_key"], enc_body),
                "x-replay-info": "replay",
            }
            if authed:
                headers.update(self._token_headers())
            status, res = await self._http_post(f"https://{host}{path}", enc_body, headers)
            env = res if isinstance(res, dict) else {}
            code = env.get("code")
            if status == 200 and code == CODE_OK:
                self._content_types[host] = content_type
                data = env.get("data")
                if isinstance(data, str) and data:
                    plain = decrypt_body(data, entry["share_key"])
                    try:
                        return json.loads(plain)
                    except ValueError:
                        return plain
                return data
            msg = str(env.get("msg") or res)[:200]
            data = env.get("data")
            if isinstance(data, str) and data:
                try:
                    msg += f" | data={decrypt_body(data, entry['share_key'])[:300]}"
                except Exception:  # noqa: BLE001 - not decryptable
                    pass
            if not (
                (status == 403 and code == CODE_SIGNATURE_INVALID) or code == CODE_PROBE_RETRY or status == 400
            ):
                break
        if authed and not _retried and (code == CODE_IDENTITY_STALE or "identity error" in msg.lower()):
            if ".eufylife.com" in host:
                self._host_keys.pop(host, None)
            else:
                self._key = None
            return await self._post_signed(host, path, body, authed, True)
        raise EufyApiError(f"{path} failed (HTTP {status}/{code}): {msg}", code, status)

    def _mega_host(self, service: str) -> str:
        return f"app-{service}-{self._region}.eufy.com"

    def _security_host(self) -> str:
        shard = self._region.split("-")[0]
        return "security-app.eufylife.com" if shard == "us" else f"security-app-{shard}.eufylife.com"

    # -- login ------------------------------------------------------------

    def _login_body(self, captcha_id: str, answer: str, verify_code: str | None) -> dict[str, Any]:
        public_key, password = encrypt_login_password(self._password)
        body: dict[str, Any] = {
            "email": self._email,
            "password": password,
            "ab": self._country,
            "client_secret_info": {"public_key": public_key},
        }
        if verify_code:
            return {**body, "verify_code": verify_code, "login_id": ""}
        if captcha_id:
            return {**body, "answer": answer, "captcha_id": captcha_id, "verify_code": "", "login_id": ""}
        return {**body, "answer": "", "captcha_id": "", "verify_code": "", "login_id": ""}

    async def _generate_captcha(self) -> tuple[str, str]:
        res = await self._post_signed(self._mega_host("passport"), "/passport/generate/captcha", {}, False)
        return res.get("captcha_id", ""), res.get("item", "")

    async def login(
        self,
        captcha_id: str | None = None,
        captcha_answer: str | None = None,
        verify_code: str | None = None,
    ) -> None:
        """Log in. Raises captcha / 2FA exceptions when more input is needed."""
        verifying = bool(verify_code) and self._pending_2fa
        if not verifying:
            # a fresh attempt must not carry an old token or key
            self._auth.pop("token", None)
            self._key = None
            if not (captcha_id or self._captcha_id):
                await self._estimate_domain()
            await self._ensure_key()
        elif not self._key:
            await self._ensure_key()
        body = self._login_body(
            (captcha_id or self._captcha_id) if captcha_answer else "",
            captcha_answer or "",
            verify_code if verifying else None,
        )
        try:
            res = await self._post_signed(
                self._mega_host("passport"), "/passport/login", body, authed=verifying
            )
        except EufyApiError as err:
            if err.code in (CODE_CAPTCHA_REQUIRED, CODE_CAPTCHA_WRONG):
                self._captcha_id, image = await self._generate_captcha()
                raise EufyCaptchaRequired(self._captcha_id, image) from err
            if err.code == CODE_BAD_PASSWORD or "password" in str(err).lower():
                raise EufyAuthError(str(err)) from err
            raise
        if not isinstance(res, dict):
            raise EufyError(f"login returned no session: {str(res)[:200]}")
        user_id = res.get("ap_cloud_user_id") or res.get("user_id") or res.get("userId")
        token = res.get("auth_token") or res.get("token")
        if not user_id or not token:
            raise EufyError(f"login returned no session: {json.dumps(res)[:200]}")
        self._auth.update(
            token=token,
            user_id=user_id,
            account_user_id=res.get("user_id") or res.get("userId") or user_id,
            expires=int(res.get("token_expires_at") or 0),
        )
        self._captcha_id = ""
        if not verifying and (res.get("fa_info") or {}).get("info"):
            # keep the limited token: the code and the verify-login must carry it
            self._pending_2fa = True
            await self._post_signed(
                self._mega_host("push"),
                "/app/sendmsg/verify_code",
                {"biz_type": 1004, "message_type": 2, "transaction": str(int(time.time() * 1000))},
            )
            raise EufyTwoFactorRequired
        self._pending_2fa = False
        # re-exchange WITH the token so the gateway binds the key ident to the user
        self._key = None
        await self._ensure_key()

    # -- data -------------------------------------------------------------

    async def _authed(self, host_kind: str, path: str, body: dict[str, Any], service: str = "") -> Any:
        """Authed call; logs in first / again when the session is gone."""

        async def call() -> Any:
            host = self._security_host() if host_kind == "security" else self._mega_host(service)
            return await self._post_signed(host, path, body)

        if not self._auth.get("token"):
            await self.login()
        try:
            return await call()
        except EufyApiError as err:
            if err.status != 401 and err.code != CODE_SESSION_KICKED:
                raise
        await self.login()
        return await call()

    async def get_cameras(self) -> list[dict[str, Any]]:
        """Return all devices of the account (merged across houses)."""
        bodies: list[dict[str, Any]] = [{}]
        try:
            houses = await self._authed("mega", "/app/house/get_house_list", {}, "house")
            bodies += [{"house_id": h["house_id"]} for h in (houses or {}).get("house_infos") or []]
        except EufyApiError as err:
            _LOGGER.debug("get_house_list failed: %s", err)
        seen: dict[str, dict[str, Any]] = {}
        for body in bodies:
            data = await self._authed("mega", "/app/house/get_devs_list", body, "house")
            for dev in (data or {}).get("devices") or []:
                if dev.get("device_sn"):
                    seen[dev["device_sn"]] = dev
        return list(seen.values())

    async def get_events(self) -> list[dict[str, Any]]:
        """Return recent alarm/motion events across all devices."""
        data = await self._authed(
            "security",
            "/v1/event/app/get_all_alarm_record",
            {"device_sn": "", "end_time": 0, "start_time": 0, "num": 50,
             "pullup": True, "shared": True, "station_sn": ""},
        )
        return data if isinstance(data, list) else []

    async def get_image(self, url: str) -> bytes | None:
        """Download an image."""
        async with self._session.get(url) as resp:
            return await resp.read() if resp.status == 200 else None

    async def set_privacy(self, device: dict[str, Any], enabled: bool) -> None:
        """Turn privacy mode on or off."""
        present = {str(p.get("param_type")) for p in device.get("params") or []}
        types = [PARAM_PRIVACY_MODE] + [
            t for t in (PARAM_DEVS_SWITCH, PARAM_PRIVACY_6250) if str(t) in present
        ]
        value = "1" if enabled else "0"
        await self._authed(
            "security",
            "/v1/app/upload_devs_params",
            {
                "device_sn": device["device_sn"],
                "station_sn": device.get("station_sn", device["device_sn"]),
                "params": [{"param_type": t, "param_value": value} for t in types],
                "transaction": str(int(time.time() * 1000)),
            },
        )
