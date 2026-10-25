"""Config flow with captcha and 2FA support."""
from __future__ import annotations

from typing import Any

import logging

import voluptuous as vol
from homeassistant.config_entries import ConfigEntry, ConfigFlow, OptionsFlow
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import EufyApi, EufyAuthError, EufyCaptchaRequired, EufyError, EufyTwoFactorRequired
from .const import (
    CONF_AUTH, CONF_CAMERAS, CONF_EMAIL, CONF_LOG_PROPERTIES, CONF_PASSWORD, CONF_SCAN_INTERVAL, CONF_VERBOSE,
    DEFAULT_SCAN_INTERVAL, DOMAIN, MAX_SCAN_INTERVAL, MIN_SCAN_INTERVAL,
)

_LOGGER = logging.getLogger(__name__)

_interval_validator = vol.All(vol.Coerce(int), vol.Range(min=MIN_SCAN_INTERVAL, max=MAX_SCAN_INTERVAL))



async def _camera_options(api: EufyApi) -> dict[str, str]:
    cams = await api.get_cameras()
    return {c["device_sn"]: f"{c.get('device_name', c['device_sn'])} ({c['device_sn']})" for c in cams}


class EufyConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle the config flow."""

    VERSION = 1

    def __init__(self) -> None:
        self._api: EufyApi | None = None
        self._creds: dict[str, str] = {}
        self._captcha_id = ""
        self._captcha_image = ""
        self._options: dict[str, str] = {}
        self._error_detail = ""
        self._opts: dict[str, Any] = {}

    @staticmethod
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        return EufyOptionsFlow()

    def _vlog(self, msg: str, *args) -> None:
        if self._api and self._api.verbose:
            _LOGGER.info("[verbose] config_flow " + msg, *args)

    async def _try_login(self, step: str, errors: dict, **kwargs):
        assert self._api
        self._vlog("step=%s login attempt (inputs: %s)", step, sorted(kwargs))
        try:
            await self._api.login(**kwargs)
            self._options = await _camera_options(self._api)
        except EufyCaptchaRequired as err:
            self._vlog("captcha required")
            self._captcha_id, self._captcha_image = err.captcha_id, err.image
            return await self.async_step_captcha()
        except EufyTwoFactorRequired:
            self._vlog("2fa required")
            return await self.async_step_2fa()
        except EufyAuthError as err:
            self._vlog("auth error: %s", err)
            self._error_detail = str(err)
            errors["base"] = "invalid_auth"
        except EufyError as err:
            _LOGGER.error("Eufy login failed: %s", err, exc_info=self._api.verbose)
            self._error_detail = str(err)
            errors["base"] = "cannot_connect"
        else:
            self._vlog("login ok, cameras found: %s", self._options)
            return await self.async_step_cameras()
        return None

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        errors: dict[str, str] = {}
        self._error_detail = ""
        if user_input:
            self._creds = {k: v for k, v in user_input.items() if k not in (CONF_VERBOSE, CONF_SCAN_INTERVAL, CONF_LOG_PROPERTIES)}
            self._opts = {
                CONF_VERBOSE: user_input.get(CONF_VERBOSE, False),
                CONF_LOG_PROPERTIES: user_input.get(CONF_LOG_PROPERTIES, False),
                CONF_SCAN_INTERVAL: user_input.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
            }
            await self.async_set_unique_id(user_input[CONF_EMAIL].lower(), raise_on_progress=False)
            self._abort_if_unique_id_configured()
            self._api = EufyApi(async_get_clientsession(self.hass), user_input[CONF_EMAIL], user_input[CONF_PASSWORD],
                verbose=user_input.get(CONF_VERBOSE, False),
                country=self.hass.config.country or "US",
            )
            if result := await self._try_login("user", errors):
                return result
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_EMAIL): str,
                    vol.Required(CONF_PASSWORD): str,
                    vol.Optional(CONF_VERBOSE, default=False): bool,
                    vol.Optional(CONF_LOG_PROPERTIES, default=False): bool,
                    vol.Optional(CONF_SCAN_INTERVAL, default=DEFAULT_SCAN_INTERVAL): _interval_validator,
                }
            ),
            description_placeholders={"error": self._error_detail},
            errors=errors,
        )

    async def async_step_captcha(self, user_input: dict[str, Any] | None = None):
        errors: dict[str, str] = {}
        if user_input and user_input.get("restart"):
            return await self.async_step_user()
        if user_input and user_input["captcha"]:
            if result := await self._try_login(
                "captcha", errors, captcha_id=self._captcha_id, captcha_answer=user_input["captcha"]
            ):
                return result
        return self.async_show_form(
            step_id="captcha",
            data_schema=vol.Schema({vol.Optional("captcha", default=""): str, vol.Optional("restart", default=False): bool}),
            description_placeholders={
                "image": f"![captcha]({self._captcha_image})",
                "error": self._error_detail,
            },
            errors=errors,
        )

    async def async_step_2fa(self, user_input: dict[str, Any] | None = None):
        errors: dict[str, str] = {}
        if user_input and user_input.get("restart"):
            return await self.async_step_user()
        if user_input and user_input["code"]:
            if result := await self._try_login("2fa", errors, verify_code=user_input["code"]):
                return result
        return self.async_show_form(
            step_id="2fa",
            data_schema=vol.Schema({vol.Optional("code", default=""): str, vol.Optional("restart", default=False): bool}),
            description_placeholders={"error": self._error_detail},
            errors=errors,
        )

    async def async_step_cameras(self, user_input: dict[str, Any] | None = None):
        assert self._api
        if user_input:
            self._vlog("cameras selected: %s options=%s", user_input[CONF_CAMERAS], self._opts)
            return self.async_create_entry(
                title=self._creds[CONF_EMAIL],
                data={**self._creds, CONF_AUTH: self._api.auth, CONF_CAMERAS: user_input[CONF_CAMERAS]},
                options={CONF_CAMERAS: user_input[CONF_CAMERAS], **self._opts},
            )
        return self.async_show_form(
            step_id="cameras",
            data_schema=vol.Schema(
                {vol.Required(CONF_CAMERAS, default=list(self._options)): cv.multi_select(self._options)}
            ),
        )


class EufyOptionsFlow(OptionsFlow):
    """Cameras, verbose logging and the cloud update interval."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None):
        if user_input:
            self.hass.data[DOMAIN][self.config_entry.entry_id].vlog("options flow submitted: %s", user_input)
            return self.async_create_entry(data=user_input)
        coordinator = self.hass.data[DOMAIN][self.config_entry.entry_id]
        options = await _camera_options(coordinator.api)
        current = [c for c in coordinator.cameras if c in options]
        opts = self.config_entry.options
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_CAMERAS, default=current): cv.multi_select(options),
                    vol.Optional(CONF_VERBOSE, default=opts.get(CONF_VERBOSE, False)): bool,
                    vol.Optional(CONF_LOG_PROPERTIES, default=opts.get(CONF_LOG_PROPERTIES, False)): bool,
                    vol.Optional(
                        CONF_SCAN_INTERVAL, default=opts.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
                    ): _interval_validator,
                }
            ),
        )
