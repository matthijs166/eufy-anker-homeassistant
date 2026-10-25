"""Camera platform: live snapshot over P2P."""
from __future__ import annotations

import asyncio
import logging
import time

from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.components.ffmpeg import get_ffmpeg_manager

from .api import EufyError
from .const import DOMAIN
from .entity import EufyEntity
from .p2p import (
    P2PError,
    aac_eld_fmp4_fragment,
    aac_eld_fmp4_init,
    has_idr,
    keyframe_to_jpeg,
    sniff_codec,
)

_LOGGER = logging.getLogger(__name__)

SNAPSHOT_MAX_AGE_S = 10
IDLE_STOP_S = 15
MAX_GOP_BYTES = 8_000_000
MAX_CLIENT_BUFFER = 4_000_000
MAX_VIEWER_BACKLOG = 600_000
RECONNECT_DELAY_S = 2
AUDIO_START_WAIT_S = 3


class LiveRelay:
    """Mux one shared P2P audio/video stream to MPEG-TS over a loopback TCP socket.

    The latest GOP is cached so a new viewer starts decoding immediately.
    """

    def __init__(self, api, device, sn, ffmpeg="ffmpeg") -> None:
        self._api, self._device, self.sn = api, device, sn
        self._ffmpeg = ffmpeg
        self._server: asyncio.AbstractServer | None = None
        self._audio_server: asyncio.AbstractServer | None = None
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._idle: asyncio.TimerHandle | None = None
        self._clients: set[asyncio.StreamWriter] = set()
        self._waiting: set[asyncio.StreamWriter] = set()
        self._gop: list[bytes] = []
        self._gop_bytes = 0
        self._mux_cache = bytearray()
        self._reset_cache = False
        self._video_codec = "h264"
        self._audio_codec: str | None = None
        self._audio_config: bytes | None = None
        self._audio_eld_initialized = False
        self._audio_eld_sequence = 1
        self._audio_eld_decode_time = 0
        self._video_pending: list[bytes] = []
        self._audio_pending: list[bytes] = []
        self._video_ready: asyncio.Future | None = None
        self._audio_ready: asyncio.Future | None = None
        self._audio_writer: asyncio.StreamWriter | None = None
        self._process: asyncio.subprocess.Process | None = None
        self._output_task: asyncio.Task | None = None
        self._error_task: asyncio.Task | None = None
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
        # A late joiner waits for the next keyframe instead of replaying an old GOP, which would lag the live edge.
        if self._mux_cache:
            self._waiting.add(writer)
        else:
            self._clients.add(writer)
        if self._task is None:
            self._stop.clear()
            self._task = asyncio.create_task(self._run())
        try:
            while await reader.read(1024):
                pass
        except OSError:
            pass
        finally:
            self._clients.discard(writer)
            self._waiting.discard(writer)
            writer.close()
            if not self._clients and not self._waiting and self._task and not self._idle:
                self._idle = asyncio.get_running_loop().call_later(IDLE_STOP_S, self._stop.set)

    def _on_video(self, data: bytes) -> None:
        self._video_codec = sniff_codec(data)
        if self._video_ready and not self._video_ready.done():
            self._video_ready.set_result(True)
        if self._process and self._process.stdin and not self._process.stdin.is_closing():
            if self._process.stdin.transport.get_write_buffer_size() < MAX_CLIENT_BUFFER:
                self._process.stdin.write(data)
        else:
            self._video_pending.append(data)
            self._video_pending = self._trim_pending(self._video_pending)
        if not self._gop:
            self.codec = self._video_codec
        if has_idr(data, self.codec):
            self._gop, self._gop_bytes = [data], len(data)
            self._reset_cache = True
            return
        if not self._gop:
            return
        if self._gop_bytes < MAX_GOP_BYTES:
            self._gop.append(data)
            self._gop_bytes += len(data)

    def _on_audio(self, codec: str, data: bytes, config: bytes | None = None) -> None:
        if codec != self._audio_codec:
            self._audio_config = config
            self._audio_eld_initialized = False
            self._audio_eld_sequence = 1
            self._audio_eld_decode_time = 0
            _LOGGER.debug("Audio codec for %s: %s", self.sn, codec)
        self._audio_codec = codec
        if self._audio_ready and not self._audio_ready.done():
            self._audio_ready.set_result(codec)
        if codec == "aac-eld":
            if not self._audio_config:
                _LOGGER.debug("AAC-ELD audio for %s has no AudioSpecificConfig", self.sn)
                return
            if not self._audio_eld_initialized:
                self._write_audio(aac_eld_fmp4_init(self._audio_config))
                self._audio_eld_initialized = True
            data = aac_eld_fmp4_fragment(data, self._audio_eld_sequence, self._audio_eld_decode_time)
            self._audio_eld_sequence += 1
            self._audio_eld_decode_time += 480
        self._write_audio(data)

    def _write_audio(self, data: bytes) -> None:
        if self._audio_writer and not self._audio_writer.is_closing():
            self._audio_writer.write(data)
        else:
            self._audio_pending.append(data)
            self._audio_pending = self._trim_pending(self._audio_pending)

    @staticmethod
    def _trim_pending(frames: list[bytes]) -> list[bytes]:
        total = 0
        kept = []
        for frame in reversed(frames):
            if total + len(frame) > MAX_GOP_BYTES:
                break
            kept.append(frame)
            total += len(frame)
        return list(reversed(kept))

    def _send(self, writer: asyncio.StreamWriter, data: bytes) -> None:
        if writer.transport.get_write_buffer_size() > MAX_VIEWER_BACKLOG:
            writer.close()
            return
        writer.write(data)

    async def _accept_audio(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._audio_writer = writer
        for frame in self._audio_pending:
            writer.write(frame)
        self._audio_pending.clear()
        try:
            while await reader.read(1024):
                pass
        except OSError:
            pass
        finally:
            if self._audio_writer is writer:
                self._audio_writer = None
            writer.close()

    async def _start_muxer(self, audio_codec: str | None) -> None:
        args = [
            self._ffmpeg, "-hide_banner", "-loglevel", "error", "-fflags", "+genpts+nobuffer",
            "-flags", "low_delay", "-probesize", "64k", "-analyzeduration", "500000",
            "-thread_queue_size", "512", "-f", "hevc" if self._video_codec == "hevc" else "h264",
            "-i", "pipe:0",
        ]
        if audio_codec in ("aac-lc", "aac-eld", "g711a"):
            self._audio_server = await asyncio.start_server(self._accept_audio, "127.0.0.1", 0)
            port = self._audio_server.sockets[0].getsockname()[1]
            args.extend(["-thread_queue_size", "512"])
            if audio_codec == "g711a":
                args.extend(["-f", "alaw", "-ar", "16000", "-ac", "1"])
            elif audio_codec == "aac-eld":
                args.extend(["-f", "mov"])
            else:
                args.extend(["-f", "aac"])
            args.extend(["-i", f"tcp://127.0.0.1:{port}"])
        args.extend(["-map", "0:v:0"])
        if audio_codec in ("aac-lc", "aac-eld", "g711a"):
            args.extend(["-map", "1:a:0", "-c:a", "copy" if audio_codec == "aac-lc" else "aac"])
        args.extend([
            "-c:v", "copy", "-bsf:v", "dump_extra=freq=keyframe",
            "-muxdelay", "0", "-muxpreload", "0", "-flush_packets", "1",
            "-mpegts_flags", "+resend_headers", "-f", "mpegts", "pipe:1",
        ])
        self._process = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._output_task = asyncio.create_task(self._read_muxed_output())
        self._error_task = asyncio.create_task(self._read_muxer_errors())
        if self._process.stdin:
            for frame in self._video_pending:
                self._process.stdin.write(frame)
        self._video_pending.clear()

    async def _read_muxed_output(self) -> None:
        if not self._process or not self._process.stdout:
            return
        while chunk := await self._process.stdout.read(1316):
            if self._reset_cache:
                # Keep only the current GOP so new viewers start at the live edge.
                self._reset_cache = False
                self._mux_cache.clear()
                self._clients |= self._waiting
                self._waiting.clear()
            self._mux_cache.extend(chunk)
            if len(self._mux_cache) > MAX_GOP_BYTES:
                del self._mux_cache[: len(self._mux_cache) - MAX_GOP_BYTES]
                while self._mux_cache and self._mux_cache[0] != 0x47:
                    del self._mux_cache[0]
            for writer in list(self._clients):
                self._send(writer, chunk)

    async def _read_muxer_errors(self) -> None:
        if not self._process or not self._process.stderr:
            return
        error = await self._process.stderr.read()
        if error:
            _LOGGER.debug("FFmpeg relay for %s: %s", self.sn, error.decode(errors="ignore").strip())

    async def _stop_muxer(self) -> None:
        if self._audio_server:
            self._audio_server.close()
            await self._audio_server.wait_closed()
            self._audio_server = None
        if self._audio_writer:
            self._audio_writer.close()
            self._audio_writer = None
        process, self._process = self._process, None
        if process:
            if process.stdin:
                process.stdin.close()
            try:
                await asyncio.wait_for(process.wait(), 3)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
        for task in (self._output_task, self._error_task):
            if task:
                await asyncio.gather(task, return_exceptions=True)
        self._output_task = self._error_task = None

    async def _run(self) -> None:
        try:
            while not self._stop.is_set():
                session = None
                stream_task = None
                try:
                    self._video_pending, self._audio_pending = [], []
                    self._audio_codec = None
                    self._audio_config = None
                    self._audio_eld_initialized = False
                    self._audio_eld_sequence = 1
                    self._audio_eld_decode_time = 0
                    loop = asyncio.get_running_loop()
                    self._video_ready = loop.create_future()
                    self._audio_ready = loop.create_future()
                    session = await self._api.open_live_session(self._device)
                    stream_task = asyncio.create_task(
                        session.stream(self._on_video, self._stop, on_audio=self._on_audio)
                    )
                    ready, _ = await asyncio.wait(
                        (self._video_ready, stream_task), return_when=asyncio.FIRST_COMPLETED
                    )
                    if stream_task in ready:
                        await stream_task
                    audio_codec = None
                    if not self._stop.is_set():
                        try:
                            audio_codec = await asyncio.wait_for(
                                asyncio.shield(self._audio_ready), AUDIO_START_WAIT_S
                            )
                        except asyncio.TimeoutError:
                            pass
                        await self._start_muxer(audio_codec)
                        if self._audio_writer:
                            for frame in self._audio_pending:
                                self._audio_writer.write(frame)
                            self._audio_pending.clear()
                        completed, _ = await asyncio.wait(
                            (stream_task, self._output_task), return_when=asyncio.FIRST_COMPLETED
                        )
                        if self._output_task in completed and not self._stop.is_set():
                            raise P2PError(f"FFmpeg relay for {self.sn} stopped unexpectedly")
                        await stream_task
                except Exception as err:  # noqa: BLE001 - relay must survive any stream failure
                    _LOGGER.debug("Live stream of %s failed: %s", self.sn, err)
                    if not self._clients and not self._waiting:
                        break
                    await asyncio.sleep(RECONNECT_DELAY_S)
                finally:
                    if stream_task and not stream_task.done():
                        stream_task.cancel()
                        await asyncio.gather(stream_task, return_exceptions=True)
                    await self._stop_muxer()
                    if session:
                        await session.close()
                    self._gop, self._gop_bytes = [], 0
                    self._mux_cache.clear()
                    self._video_ready = self._audio_ready = None
        finally:
            self._task = None

    async def async_halt(self) -> None:
        """Drop all viewers and end the P2P session; a new viewer restarts it."""
        self._stop.set()
        for writer in list(self._clients | self._waiting):
            writer.close()
        self._gop, self._gop_bytes = [], 0

    async def async_close(self) -> None:
        self._stop.set()
        if self._idle:
            self._idle.cancel()
        for writer in list(self._clients | self._waiting):
            writer.close()
        if self._server:
            self._server.close()
            self._server = None
        task = self._task
        if task:
            # A stuck P2P session must not block unload, otherwise a reload never completes.
            _, pending = await asyncio.wait((task,), timeout=5)
            if pending:
                task.cancel()
                await asyncio.wait((task,), timeout=5)


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    coordinator.vlog("camera platform setup: %s", list(coordinator.data))
    ffmpeg = get_ffmpeg_manager(hass).binary
    async_add_entities(EufyCamera(coordinator, sn, ffmpeg) for sn in coordinator.data)


class EufyCamera(EufyEntity, Camera):
    """Live frame over P2P, falling back to the last stored event image."""

    _attr_name = None
    _attr_supported_features = CameraEntityFeature.STREAM
    def __init__(self, coordinator, sn, ffmpeg) -> None:
        EufyEntity.__init__(self, coordinator, sn)
        Camera.__init__(self)
        self._attr_unique_id = f"{sn}_camera"
        self._lock = asyncio.Lock()
        self._snapshot: tuple[float, bytes] | None = None
        self._relay = LiveRelay(coordinator.api, self.info["device"], sn, ffmpeg)

    @property
    def _private(self) -> bool:
        return bool(self.info.get("privacy"))

    def _handle_coordinator_update(self) -> None:
        if self._private:
            self.hass.async_create_task(self._relay.async_halt())
        super()._handle_coordinator_update()

    async def stream_source(self) -> str | None:
        if self._private:
            return None
        return await self._relay.async_url()

    async def async_will_remove_from_hass(self) -> None:
        await self._relay.async_close()

    async def async_camera_image(self, width=None, height=None):
        if self._private:
            return None
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
