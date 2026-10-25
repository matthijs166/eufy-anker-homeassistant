"""Live stream tests against a real camera (same env/credentials as test_integration)."""
from __future__ import annotations

import asyncio
import time

import pytest
from aiohttp import ClientSession

from test_integration import _login, api_mod, EMAIL, PASSWORD  # noqa: F401

import importlib

p2p = importlib.import_module("eufy_anker_ha.p2p")

pytestmark = [
    pytest.mark.skipif(not (EMAIL and PASSWORD), reason="EUFY_EMAIL / EUFY_PASSWORD not set"),
]

STREAM_SECONDS = 8


@pytest.mark.asyncio
async def test_live_stream_delivers_frames():
    async with ClientSession() as session:
        api = await _login(session)
        device = (await api.get_cameras())[0]

        frames: list[bytes] = []
        first_at: list[float] = []
        stop = asyncio.Event()
        t0 = time.monotonic()

        def on_video(data: bytes) -> None:
            if not frames:
                first_at.append(time.monotonic() - t0)
            frames.append(data)

        live = await api.open_live_session(device)
        try:
            task = asyncio.create_task(live.stream(on_video, stop))
            await asyncio.sleep(STREAM_SECONDS)
            stop.set()
            await asyncio.wait_for(task, 5)
        finally:
            await live.close()

        assert frames, "no video frames received"
        codec = p2p.sniff_codec(frames[0])
        assert any(p2p.has_idr(f, codec) for f in frames), "no keyframe in stream"
        print(f"\nLIVE: {len(frames)} frames in {STREAM_SECONDS}s, codec={codec}, first frame after {first_at[0]:.1f}s")
        assert len(frames) > STREAM_SECONDS, "frame rate unexpectedly low"

        keyframe = next(f for f in frames if p2p.has_idr(f, codec))
        jpeg = await p2p.keyframe_to_jpeg(codec, keyframe)
        assert jpeg[:2] == b"\xff\xd8", "keyframe did not decode to JPEG"


@pytest.mark.asyncio
async def test_live_relay_serves_cached_gop_to_second_viewer():
    camera = pytest.importorskip("eufy_anker_ha.camera", reason="homeassistant not installed")
    async with ClientSession() as session:
        api = await _login(session)
        device = (await api.get_cameras())[0]
        relay = camera.LiveRelay(api, device, device["device_sn"])
        try:
            host, port = (await relay.async_url()).removeprefix("tcp://").split(":")

            async def read_some(n: int, timeout: float) -> tuple[bytes, float]:
                start = time.monotonic()
                reader, writer = await asyncio.open_connection(host, int(port))
                try:
                    data = await asyncio.wait_for(reader.readexactly(n), timeout)
                finally:
                    writer.close()
                return data, time.monotonic() - start

            first, cold = await read_some(20_000, 30)
            assert first[0] == 0x47 and all(first[offset] == 0x47 for offset in range(0, len(first), 188))
            second, warm = await read_some(20_000, 5)
            print(f"\nRELAY: cold start {cold:.1f}s, warm start {warm:.2f}s")
            assert warm < 1.0, "second viewer did not get the cached GOP immediately"
        finally:
            await relay.async_close()
