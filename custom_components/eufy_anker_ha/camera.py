"""Camera platform: live snapshot over P2P."""
from __future__ import annotations

import asyncio
import logging
import time

from homeassistant.components.camera import Camera
from homeassistant.components.ffmpeg import get_ffmpeg_manager

from .api import EufyError
from .const import DOMAIN
from .entity import EufyEntity
from .p2p import P2PError, has_idr, keyframe_to_jpeg, sniff_codec

_LOGGER = logging.getLogger(__name__)

SNAPSHOT_MAX_AGE_S = 10
IDLE_STOP_S = 15
MAX_GOP_BYTES = 8_000_000
MAX_CLIENT_BUFFER = 4_000_000
RECONNECT_DELAY_S = 2


class LiveRelay:
    """One shared P2P stream per camera, fanned out as raw Annex-B over a loopback TCP socket.

    The latest GOP is cached so a new viewer starts decoding immediately.
    """

    def __init__(self, api, device, sn) -> None:
        self._api, self._device, self.sn = api, device, sn
        self._server: asyncio.AbstractServer | None = None
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._idle: asyncio.TimerHandle | None = None
        self._clients: dict[asyncio.StreamWriter, bool] = {}
        self._gop: list[bytes] = []
        self._gop_bytes = 0
        self.codec = "h264"

    async def async_url(self) -> str:
        if self._server is None:
            self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        return f"tcp://127.0.0.1:{self._server.sockets[0].getsockname()[1]}"

    @property
    def keyframe(self) -> tuple[str, bytes] | None:
        return (self.codec, self._gop[0]) if self._gop else None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._idle:
            self._idle.cancel()
            self._idle = None
        if self._gop:
            writer.write(b"".join(self._gop))
        self._clients[writer] = bool(self._gop)
        if self._task is None:
            self._stop.clear()
            self._task = asyncio.create_task(self._run())
        try:
            while await reader.read(1024):
                pass
        except OSError:
            pass
        finally:
            self._clients.pop(writer, None)
            writer.close()
            if not self._clients and self._task and not self._idle:
                self._idle = asyncio.get_running_loop().call_later(IDLE_STOP_S, self._stop.set)

    def _on_video(self, data: bytes) -> None:
        if not self._gop:
            self.codec = sniff_codec(data)
        if has_idr(data, self.codec):
            self._gop, self._gop_bytes = [data], len(data)
            for writer, synced in list(self._clients.items()):
                if synced:
                    self._send(writer, data)
                else:
                    writer.write(data)
                    self._clients[writer] = True
            return
        if not self._gop:
            return
        if self._gop_bytes < MAX_GOP_BYTES:
            self._gop.append(data)
            self._gop_bytes += len(data)
        for writer, synced in list(self._clients.items()):
            if synced:
                self._send(writer, data)

    def _send(self, writer: asyncio.StreamWriter, data: bytes) -> None:
        if writer.transport.get_write_buffer_size() > MAX_CLIENT_BUFFER:
            writer.close()
            return
        writer.write(data)

    async def _run(self) -> None:
        try:
            while not self._stop.is_set():
                session = None
                try:
                    session = await self._api.open_live_session(self._device)
                    await session.stream(self._on_video, self._stop)
                except (P2PError, EufyError, OSError) as err:
                    _LOGGER.debug("Live stream of %s failed: %s", self.sn, err)
                    if not self._clients:
                        break
                    await asyncio.sleep(RECONNECT_DELAY_S)
                finally:
                    if session:
                        await session.close()
                    self._gop, self._gop_bytes = [], 0
                    for writer in self._clients:
                        self._clients[writer] = False
        finally:
            self._task = None

    async def async_close(self) -> None:
        self._stop.set()
        if self._idle:
            self._idle.cancel()
        for writer in list(self._clients):
            writer.close()
        if self._server:
            self._server.close()
            self._server = None
        if self._task:
            await asyncio.gather(self._task, return_exceptions=True)


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    coordinator.vlog("camera platform setup: %s", list(coordinator.data))
    async_add_entities(EufyCamera(coordinator, sn) for sn in coordinator.data)


class EufyCamera(EufyEntity, Camera):
    """Live frame over P2P, falling back to the last stored event image."""

    _attr_name = None

    def __init__(self, coordinator, sn) -> None:
        EufyEntity.__init__(self, coordinator, sn)
        Camera.__init__(self)
        self._attr_unique_id = f"{sn}_camera"
        self._lock = asyncio.Lock()
        self._snapshot: tuple[float, bytes] | None = None
        self._relay = LiveRelay(coordinator.api, self.info["device"], sn)
        # Raw Annex-B carries no timestamps.
        self.stream_options["use_wallclock_as_timestamps"] = True

    async def stream_source(self) -> str:
        return await self._relay.async_url()

    async def async_will_remove_from_hass(self) -> None:
        await self._relay.async_close()

    async def async_camera_image(self, width=None, height=None):
        live = self._relay.keyframe
        if live:
            try:
                return await keyframe_to_jpeg(*live, get_ffmpeg_manager(self.hass).binary)
            except P2PError as err:
                _LOGGER.debug("Decoding live keyframe of %s failed: %s", self.sn, err)
        async with self._lock:
            if self._snapshot and time.monotonic() - self._snapshot[0] < SNAPSHOT_MAX_AGE_S:
                return self._snapshot[1]
            api = self.coordinator.api
            try:
                image = await api.get_snapshot(self.info["device"], get_ffmpeg_manager(self.hass).binary)
                self._snapshot = (time.monotonic(), image)
                return image
            except (P2PError, EufyError, OSError) as err:
                _LOGGER.debug("Live snapshot of %s failed, using stored image: %s", self.sn, err)
            url = self.info.get("image_url")
            image = await api.get_image(url) if url else None
            self.coordinator.vlog("camera image %s -> %s bytes", self.sn, len(image) if image else None)
            return image
