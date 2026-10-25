"""Minimal Eufy P2P (ThroughTek PPCS over UDP) client: connect to one camera and grab a live keyframe.

Protocol details follow the reverse-engineered mega-yfue/eufy-sdk (src/transport/p2p). Only the
own-session camera path is implemented (level-1 / clear control seal, no relay, no level-2 key).
"""
from __future__ import annotations

import asyncio
import json
import logging
import socket
import struct
import time
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_LOGGER = logging.getLogger(__name__)

MAGIC = b"XZYH"
LOCAL_LOOKUP_PORT = 32108
HEARTBEAT_S = 5.0
LOOKUP_RETRY_S = 1.0
KEEPALIVE_S = 2.0
LIVE_START_RETRANSMIT_S = 0.15
LIVE_START_ACK_DEADLINE_S = 3.0
SEQ_LOOKBACK = 0x8000
STALE_DEPTH = 1024
REORDER_WAIT_S = 0.25
VIDEO_REORDER_WAIT_S = 0.7
REORDER_MAX = 128

T_LOCAL_LOOKUP = b"\xf1\x30"
T_LOOKUP_KEY = b"\xf1\x26"
T_LOOKUP_KEY2 = b"\xf1\x6a"
T_CHECK_CAM = b"\xf1\x41"
T_PING = b"\xf1\xe0"
T_PONG = b"\xf1\xe1"
T_DATA = b"\xf1\xd0"
T_ACK = b"\xf1\xd1"
T_END = b"\xf1\xf0"
R_LOOKUP_ADDR = b"\xf1\x40"
R_CAM_ID = b"\xf1\x42"

DT_DATA, DT_VIDEO = 0, 1

CMD_GATEWAYINFO = 1100
CMD_CONTROL_PAYLOAD = 1700
CMD_START_LIVE = 1000
CMD_STOP_MEDIA = 1004
CMD_KEEPALIVE = 1139
CMD_VIDEO_FRAME = 1300
STATION_CHANNEL = 255
FRAME_TYPE_L1 = 11

_CLOUD_TABLE = bytes.fromhex(
    "4959433db5bf6da347534f6165e371e9677f02030badb3892b2f35c16b8b959711e5a70deff1050783fb9d3bc5c713171d1f2529d3df"
)


class P2PError(Exception):
    """P2P connect or stream failure."""


def decode_cloud_ips(data: str) -> list[tuple[str, int]]:
    """Decode a device's p2p_conn string into the PPCS lookup servers (port 32100)."""
    encoded = data.split(":")[0]
    out = bytearray(len(encoded) // 2)
    for i in range(len(out)):
        z = 0x39
        for j in range(i):
            z ^= out[j]
        x = ord(data[i * 2 + 1]) - 65
        y = (ord(data[i * 2]) - 65) * 0x10
        out[i] = (z ^ _CLOUD_TABLE[i % len(_CLOUD_TABLE)] ^ (x + y)) & 0xFF
    return [(ip, 32100) for ip in out.decode("utf-8", "ignore").split(",") if ip]


def _pad_len(text: str, chunk: int) -> bytes:
    raw = text.encode()
    size = chunk if len(raw) < chunk else -(-len(raw) // chunk) * chunk
    return raw.ljust(size, b"\0")


def did_to_bytes(did: str) -> bytes:
    a = did.split("-")
    return (_pad_len(a[0], 8) + struct.pack(">I", int(a[1])) + _pad_len(a[2], 8))[:20]


def _frame_message(msg_type: bytes, payload: bytes = b"") -> bytes:
    return msg_type + struct.pack(">H", len(payload)) + payload


def _encode_address(host: str, port: int) -> bytes:
    o = [int(p) for p in host.split(".")]
    return struct.pack(">H", 2) + struct.pack("<H", port) + bytes([o[3], o[2], o[1], o[0]]) + b"\0" * 8


def _read_address(buf: bytes, offset: int) -> tuple[str, int]:
    return (
        f"{buf[offset + 7]}.{buf[offset + 6]}.{buf[offset + 5]}.{buf[offset + 4]}",
        struct.unpack_from("<H", buf, offset + 2)[0],
    )


def _command_header(seq: int, cmd: int, data_type: int = DT_DATA) -> bytes:
    return bytes([0xD1, data_type]) + struct.pack(">H", seq) + MAGIC + struct.pack("<H", cmd)


def _raw_payload(data: bytes, channel: int, sign_code: int, magic: tuple[int, int] = (1, 0), stream_id: int = 0) -> bytes:
    return struct.pack("<H", len(data)) + b"\0\0" + bytes(magic) + bytes([channel & 0xFF, sign_code & 0xFF, stream_id & 0xFF, 0]) + data


def _void_payload(channel: int) -> bytes:
    return b"\0\0\0\0\x01\0" + bytes([channel & 0xFF, 0, 0, 0])


def _ecb(data: bytes, key: bytes, encrypt: bool) -> bytes:
    c = Cipher(algorithms.AES(key), modes.ECB())
    op = c.encryptor() if encrypt else c.decryptor()
    return op.update(data) + op.finalize()


def _zero_pad(data: bytes) -> bytes:
    size = max(16, -(-len(data) // 16) * 16)
    return data.ljust(size, b"\0")


def level1_key(sn: str, did: str) -> bytes:
    i = did.index("-")
    return f"{sn[-7:]}{did[i:i + 9]}".encode()


def _nal_units(data: bytes) -> list[bytes]:
    units, i, n = [], 0, len(data)
    starts = []
    while i + 3 <= n:
        if data[i] == 0 and data[i + 1] == 0 and (data[i + 2] == 1 or (data[i + 2] == 0 and i + 3 < n and data[i + 3] == 1)):
            i += 3 if data[i + 2] == 1 else 4
            starts.append(i)
        else:
            i += 1
    for k, s in enumerate(starts):
        end = n if k + 1 == len(starts) else starts[k + 1]
        units.append(data[s:end])
    return [u for u in units if u]


def sniff_codec(data: bytes) -> str:
    """Return 'hevc' or 'h264' from the first NAL header."""
    nals = _nal_units(data)
    if not nals:
        return "h264"
    b = nals[0][0]
    if (b >> 1) & 0x3F == 32:
        return "hevc"
    return "h264" if (b & 0x1F) in (1, 5, 6, 7, 8, 9) else "hevc"


def has_idr(data: bytes, codec: str) -> bool:
    for nal in _nal_units(data):
        b = nal[0]
        if codec == "hevc" and 16 <= (b >> 1) & 0x3F <= 21:
            return True
        if codec == "h264" and (b & 0x1F) == 5:
            return True
    return False


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, session: "P2PSession") -> None:
        self._s = session

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            self._s._on_message(data, addr)
        except Exception:  # noqa: BLE001 - never let a bad datagram kill the loop
            _LOGGER.exception("p2p: error handling datagram")

    def error_received(self, exc: Exception) -> None:
        _LOGGER.debug("p2p socket error: %s", exc)


class P2PSession:
    """One UDP session to a camera that serves itself (not behind a HomeBase)."""

    def __init__(
        self,
        sn: str,
        did: str,
        account_id: str,
        *,
        cloud_addrs: list[tuple[str, int]] | None = None,
        dsk_key: str | None = None,
        local_addr: str | None = None,
        channel: int = 0,
    ) -> None:
        self.sn, self.did, self.account_id, self.channel = sn, did, account_id, channel
        self._cloud_addrs = cloud_addrs or []
        self._dsk = dsk_key
        self._local_addr = local_addr
        self._l1 = level1_key(sn, did)
        self._transport: asyncio.DatagramTransport | None = None
        self._peer: tuple[str, int] | None = None
        self._connected = asyncio.Event()
        self._closed = False
        self._tasks: list[asyncio.Task] = []
        self._seq = 0
        self._last_pong: bytes = b""
        self._self_host: str | None = None
        self._cipher_id: int | None = None
        self._gateway = asyncio.Event()
        self._clear_count = 0
        self._unacked_starts: dict[int, tuple[bytes, float]] = {}
        self._start_acked = asyncio.Event()
        self._rsa = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        self._rsa_modulus = format(self._rsa.public_key().public_numbers().n, "0256x")
        self._last_seq: dict[int, int] = {}
        self._held: dict[int, dict[int, bytes]] = {}
        self._reorder_timers: dict[int, asyncio.TimerHandle] = {}
        self._pending: dict[int, dict[str, Any]] = {}
        self._frame_cb: Callable[[int, int, bytes], None] | None = None

    # -- connection -----------------------------------------------------------

    async def connect(self, timeout: float = 20.0) -> None:
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        except OSError:
            pass
        sock.bind(("0.0.0.0", 0))
        sock.setblocking(False)
        self._transport, _ = await loop.create_datagram_endpoint(lambda: _Protocol(self), sock=sock)
        self._self_host = await loop.run_in_executor(None, _local_ip)
        self._tasks.append(asyncio.ensure_future(self._lookup_loop()))
        try:
            await asyncio.wait_for(self._connected.wait(), timeout)
        except asyncio.TimeoutError as err:
            await self.close()
            raise P2PError(f"P2P connect to {self.sn} timed out after {timeout:.0f}s") from err

    async def _lookup_loop(self) -> None:
        while not self._connected.is_set() and not self._closed:
            self._send(("255.255.255.255", LOCAL_LOOKUP_PORT), T_LOCAL_LOOKUP, b"\0\0")
            if self._local_addr:
                self._send((self._local_addr, LOCAL_LOOKUP_PORT), T_LOCAL_LOOKUP, b"\0\0")
            if self._dsk and self._cloud_addrs and self._transport:
                port = self._transport.get_extra_info("sockname")[1]
                if self._self_host:
                    kind = T_LOOKUP_KEY
                    payload = did_to_bytes(self.did) + _encode_address(self._self_host, port) + b"\x02\x05\x01\x05" + self._dsk.encode() + b"\0" * 4
                else:
                    kind = T_LOOKUP_KEY2
                    payload = did_to_bytes(self.did) + self._dsk.encode() + b"\0" * 4
                for addr in self._cloud_addrs:
                    self._send(addr, kind, payload)
            await asyncio.sleep(LOOKUP_RETRY_S)

    def _send(self, addr: tuple[str, int], msg_type: bytes, payload: bytes = b"") -> None:
        if self._transport and not self._transport.is_closing():
            try:
                self._transport.sendto(_frame_message(msg_type, payload), addr)
            except OSError as err:
                _LOGGER.debug("p2p send to %s failed: %s", addr, err)

    def _begin_check_cam(self, addr: tuple[str, int]) -> None:
        payload = did_to_bytes(self.did) + b"\0\0\0"
        host, port = addr
        self._send(addr, T_CHECK_CAM, payload)
        for p in range(port - 3, port + 4):
            if p != port and p > 0:
                self._send((host, p), T_CHECK_CAM, payload)

    def _on_connected(self, addr: tuple[str, int]) -> None:
        if self._connected.is_set():
            return
        self._peer = addr
        self._connected.set()
        _LOGGER.debug("p2p %s connected %s:%s", self.sn, *addr)
        self._send_command(CMD_GATEWAYINFO, STATION_CHANNEL)
        self._send(addr, T_PING)
        self._tasks.append(asyncio.ensure_future(self._heartbeat_loop()))

    async def _heartbeat_loop(self) -> None:
        while not self._closed:
            await asyncio.sleep(HEARTBEAT_S)
            if self._peer:
                self._send(self._peer, T_PING, self._last_pong)

    # -- inbound --------------------------------------------------------------

    def _on_message(self, msg: bytes, addr: tuple[str, int]) -> None:
        head = msg[:2]
        if head == T_CHECK_CAM:  # LOCAL_LOOKUP_RESP shares f141
            if not self._connected.is_set():
                self._begin_check_cam(addr)
        elif head == R_LOOKUP_ADDR:
            if not self._connected.is_set() and len(msg) >= 12:
                host, port = _read_address(msg, 4)
                if host != "0.0.0.0":
                    self._begin_check_cam((host, port))
        elif head == R_CAM_ID:
            self._on_connected(addr)
        elif head == T_END:
            if addr == self._peer:
                asyncio.ensure_future(self.close())
        elif head == T_PONG:
            self._last_pong = msg[4:] if len(msg) > 4 else b""
        elif head == T_PING:
            self._send(addr, T_PONG)
        elif head == T_ACK:
            self._on_ack(msg)
        elif head == T_DATA:
            if self._connected.is_set():
                self._on_data(msg, addr)

    def _on_ack(self, msg: bytes) -> None:
        if len(msg) < 8 or msg[4] != 0xD1 or msg[5] != DT_DATA:
            return
        count = struct.unpack_from(">H", msg, 6)[0]
        for i in range(count):
            if 10 + 2 * i > len(msg):
                break
            if self._unacked_starts.pop(struct.unpack_from(">H", msg, 8 + 2 * i)[0], None) is not None:
                self._start_acked.set()

    def _on_data(self, msg: bytes, addr: tuple[str, int]) -> None:
        if len(msg) < 8:
            return
        data_type = msg[5]
        seq = struct.unpack_from(">H", msg, 6)[0]
        self._send(addr, T_ACK, bytes([0xD1, data_type]) + struct.pack(">HH", 1, seq))
        body = msg[8:]
        prev = self._last_seq.get(data_type)
        advance = 1 if prev is None else (seq - prev) & 0xFFFF
        if advance == 0:
            return
        if advance > SEQ_LOOKBACK:
            if 0x10000 - advance <= STALE_DEPTH:
                return
            self._clear_reorder(data_type)
            self._pending.pop(data_type, None)
            self._last_seq[data_type] = seq
            self._reassemble(data_type, body)
            return
        if advance == 1:
            self._last_seq[data_type] = seq
            self._reassemble(data_type, body)
            self._drain(data_type)
            return
        held = self._held.setdefault(data_type, {})
        held.setdefault(seq, body)
        if len(held) > REORDER_MAX:
            self._abandon_hole(data_type)
        elif data_type not in self._reorder_timers:
            wait = VIDEO_REORDER_WAIT_S if data_type == DT_VIDEO else REORDER_WAIT_S
            self._reorder_timers[data_type] = asyncio.get_running_loop().call_later(wait, self._on_reorder_timeout, data_type)

    def _on_reorder_timeout(self, data_type: int) -> None:
        self._reorder_timers.pop(data_type, None)
        if self._held.get(data_type):
            self._abandon_hole(data_type)

    def _clear_reorder(self, data_type: int) -> None:
        timer = self._reorder_timers.pop(data_type, None)
        if timer:
            timer.cancel()
        self._held.pop(data_type, None)

    def _drain(self, data_type: int) -> None:
        held = self._held.get(data_type)
        if not held:
            return
        timer = self._reorder_timers.pop(data_type, None)
        if timer:
            timer.cancel()
        while True:
            nxt = (self._last_seq[data_type] + 1) & 0xFFFF
            body = held.pop(nxt, None)
            if body is None:
                break
            self._last_seq[data_type] = nxt
            self._reassemble(data_type, body)
        if held:
            wait = VIDEO_REORDER_WAIT_S if data_type == DT_VIDEO else REORDER_WAIT_S
            self._reorder_timers[data_type] = asyncio.get_running_loop().call_later(wait, self._on_reorder_timeout, data_type)
        else:
            self._held.pop(data_type, None)

    def _abandon_hole(self, data_type: int) -> None:
        held = self._held[data_type]
        last = self._last_seq[data_type]
        earliest = min(held, key=lambda s: (s - last) & 0xFFFF)
        self._pending.pop(data_type, None)
        self._last_seq[data_type] = (earliest - 1) & 0xFFFF
        self._drain(data_type)

    def _reassemble(self, data_type: int, datagram: bytes) -> None:
        pending = self._pending.pop(data_type, None)
        body = datagram
        if pending and "header" not in pending:
            body = pending["partial"] + datagram
        elif pending:
            need = pending["header"][1] - pending["length"]
            taken = datagram[:need]
            pending["chunks"].append(taken)
            pending["length"] += len(taken)
            body = datagram[len(taken):]
            if pending["length"] < pending["header"][1]:
                self._pending[data_type] = pending
                return
            self._handle_frame(pending["header"], b"".join(pending["chunks"]))
        while len(body) >= 16 and body[:4] == MAGIC:
            cmd, length = struct.unpack_from("<HI", body, 4)
            header = (cmd, length, body[12], body[13])
            payload = body[16:]
            if len(payload) < length:
                self._pending[data_type] = {"header": header, "chunks": [payload], "length": len(payload)}
                return
            self._handle_frame(header, payload[:length])
            body = body[16 + length:]
        if 0 < len(body) < 16 and MAGIC.startswith(body[:4]):
            self._pending[data_type] = {"partial": body}

    def _handle_frame(self, header: tuple[int, int, int, int], payload: bytes) -> None:
        cmd, _, _channel, sign = header
        if cmd == CMD_GATEWAYINFO:
            data = payload
            if sign > 0 and data and len(data) % 16 == 0:
                data = _ecb(data, self._l1, False)
            if len(data) >= 2 and self._cipher_id is None:
                self._cipher_id = struct.unpack_from("<H", data, 0)[0]
                _LOGGER.debug("p2p %s gateway cipher_id=%s", self.sn, self._cipher_id)
                self._gateway.set()
        elif cmd == CMD_VIDEO_FRAME and self._frame_cb:
            self._frame_cb(cmd, sign, payload)

    # -- outbound -------------------------------------------------------------

    def _next_seq(self) -> int:
        seq = self._seq
        self._seq = (self._seq + 1) & 0xFFFF
        return seq

    def _send_data(self, data: bytes) -> None:
        if self._peer:
            self._send(self._peer, T_DATA, data)

    def _send_command(self, cmd: int, channel: int) -> None:
        self._send_data(_command_header(self._next_seq(), cmd) + _void_payload(channel))

    def _start_json(self, clear_msg_id: int | None) -> bytes:
        if clear_msg_id is not None:
            body = {"commandType": CMD_START_LIVE, "data": {"accountId": self.account_id, "encryptkey": self._rsa_modulus, "msg_id": clear_msg_id, "streamtype": 1}}
        else:
            now = int(time.time() * 1000)
            body = {
                "commandType": CMD_START_LIVE,
                "data": {
                    "cmd": CMD_START_LIVE, "account_id": self.account_id, "accountId": self.account_id,
                    "mValueStrSub": self.account_id, "mChannel": self.channel, "mValue3": 0, "mValue5": 0,
                    "msg_id": 1, "camera_type": 0, "entrytype": 0, "extValue": CMD_START_LIVE, "ivalue": 1,
                    "restore": 0, "streamtype": 2, "video_type": 12, "timestamp": now,
                    "transaction": str(now), "encryptkey": self._rsa_modulus,
                },
            }
        return json.dumps(body, separators=(",", ":")).encode()

    def _send_start(self) -> None:
        if self._cipher_id == 0:
            self._clear_count = (self._clear_count % 0xFF) + 1
            payload = _raw_payload(self._start_json(self._clear_count), self.channel, 0, (1, self._clear_count), 0)
        else:
            enc = _ecb(_zero_pad(self._start_json(None)), self._l1, True)
            payload = _raw_payload(enc, self.channel, 1, (1, 0), FRAME_TYPE_L1)
        seq = self._next_seq()
        data = _command_header(seq, CMD_CONTROL_PAYLOAD) + payload
        self._unacked_starts[seq] = (data, time.monotonic())
        self._send_data(data)

    def _send_stop(self) -> None:
        body = struct.pack("<I", self.channel)
        if self._cipher_id == 0:
            self._clear_count = (self._clear_count % 0xFF) + 1
            data = _command_header(self._next_seq(), CMD_STOP_MEDIA) + _raw_payload(body, self.channel, 0, (1, self._clear_count))
            self._send_data(data)
        else:
            self._send_command(CMD_STOP_MEDIA, self.channel)

    # -- video ----------------------------------------------------------------

    def decode_video(self, payload: bytes, sign: int) -> bytes | None:
        if len(payload) < 22:
            return None
        length = struct.unpack_from("<I", payload, 0)[0]
        start = 22
        key = None
        if sign > 0 and length >= 128:
            if len(payload) < 150:
                return None
            try:
                key = self._rsa.decrypt(payload[22:150], padding.PKCS1v15())
            except ValueError:
                return None
            if len(key) not in (16, 32):
                return None
            start = 151
        if key:
            head = _ecb(payload[start:start + 128], key[:32] if len(key) >= 32 else key[:16], False) if len(payload) >= start + 128 else b""
            return head + payload[start + 128:start + length]
        return payload[start:start + length]

    async def capture_keyframe(self, timeout: float = 15.0) -> tuple[str, bytes]:
        """Start the live stream and return (codec, Annex-B bytes) of the first decodable keyframe."""
        loop = asyncio.get_running_loop()
        result: asyncio.Future = loop.create_future()
        frames: list[bytes] = []

        def on_frame(_cmd: int, sign: int, payload: bytes) -> None:
            if result.done():
                return
            data = self.decode_video(payload, sign)
            if not data:
                return
            codec = sniff_codec(data)
            frames.append(data)
            if has_idr(data, codec):
                result.set_result((codec, data))

        self._frame_cb = on_frame
        try:
            try:
                await asyncio.wait_for(self._gateway.wait(), 3.0)
            except asyncio.TimeoutError:
                _LOGGER.debug("p2p %s no gateway info reply, starting at level 1", self.sn)
            deadline = loop.time() + timeout
            self._send_start()
            last_start = last_keepalive = loop.time()
            while not result.done():
                now = loop.time()
                if now >= deadline:
                    raise P2PError(f"no video keyframe from {self.sn} within {timeout:.0f}s ({len(frames)} frames seen)")
                if self._unacked_starts and now - last_start >= LIVE_START_RETRANSMIT_S:
                    for data, first in list(self._unacked_starts.values()):
                        self._send_data(data)
                    last_start = now
                    oldest = min(first for _, first in self._unacked_starts.values())
                    if time.monotonic() - oldest > LIVE_START_ACK_DEADLINE_S:
                        self._unacked_starts.clear()
                        self._send_start()
                if now - last_keepalive >= KEEPALIVE_S:
                    self._send_command(CMD_KEEPALIVE, self.channel)
                    last_keepalive = now
                await asyncio.sleep(0.05)
            return result.result()
        finally:
            self._frame_cb = None
            self._send_stop()

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._peer:
            self._send(self._peer, T_END)
        for task in self._tasks:
            task.cancel()
        for timer in self._reorder_timers.values():
            timer.cancel()
        self._reorder_timers.clear()
        if self._transport:
            self._transport.close()


def _local_ip() -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(1)
            s.connect(("8.8.8.8", 53))
            return s.getsockname()[0]
    except OSError:
        return None


async def keyframe_to_jpeg(codec: str, annexb: bytes, ffmpeg: str = "ffmpeg", timeout: float = 15.0) -> bytes:
    """Decode one Annex-B keyframe into a JPEG with ffmpeg."""
    proc = await asyncio.create_subprocess_exec(
        ffmpeg, "-loglevel", "error", "-f", codec, "-i", "pipe:0", "-frames:v", "1", "-f", "image2pipe", "-c:v", "mjpeg", "pipe:1",
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(annexb), timeout)
    except asyncio.TimeoutError as exc:
        proc.kill()
        raise P2PError("ffmpeg timed out decoding the keyframe") from exc
    if not out:
        raise P2PError(f"ffmpeg produced no image: {err.decode(errors='ignore')[:200]}")
    return out
