"""``algo_ecdh`` crypto for the Eufy (Anker) cloud.

Python port of ``core/crypto.ts`` from https://github.com/mega-yfue/eufy-sdk.

  A. Key exchange: the client public key (hex) is AES-128-CBC encrypted with a
     bootstrap "local key"; the server answers with its public key wrapped the
     same way. ECDH (P-256) -> shareKey (first 32 hex chars of the secret).
  B. Request bodies: base64(IV(16) || AES-128-CBC-PKCS7(plaintext)).
  C. x-signature = HMAC-SHA256(shareKey hex as UTF-8, ts+once[+encBody]).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
from typing import Any

from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MEGA_LOCAL_KEY_HEX = "2500a7d5617812f9d52515b2c8f20a3d"
EUFYLIFE_LOCAL_KEY_HEX = "118c12c81e211149304bd70a0c071d01"
SERVER_STATIC_PUBLIC_KEY_HEX = (
    "04c5c00c4f8d1197cc7c3167c52bf7acb054d722f0ef08dcd7e0883236e0d72a"
    "3868d9750cb47fa4619248f3d83f0f662671dadc6e2d31c2f41db0161651c7c076"
)


def gen_id() -> str:
    """32 hex chars, for X-Key-Ident / X-Request-Once."""
    return os.urandom(16).hex()


def gtoken(user_id: str) -> str:
    """gtoken header = md5(user_id) hex."""
    return hashlib.md5(user_id.encode()).hexdigest()


def _aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(padder.update(data) + padder.finalize()) + enc.finalize()


def _aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(dec.update(data) + dec.finalize()) + unpadder.finalize()


def _public_hex(key: ec.EllipticCurvePrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    ).hex()


def _load_public(hex_key: str) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(hex_key))


def encrypt_login_password(password: str) -> tuple[str, str]:
    """Return (client public key hex, base64 ciphertext) for the login body.

    One-shot ECDH against the static server key; AES-256-CBC with the full
    32-byte secret as key and its first 16 bytes as IV.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    shared = key.exchange(ec.ECDH(), _load_public(SERVER_STATIC_PUBLIC_KEY_HEX))
    ct = _aes_cbc_encrypt(shared, shared[:16], password.encode())
    return _public_hex(key), base64.b64encode(ct).decode()


def encrypt_body(plaintext: str, share_key: str) -> str:
    iv = os.urandom(16)
    ct = _aes_cbc_encrypt(bytes.fromhex(share_key)[:16], iv, plaintext.encode())
    return base64.b64encode(iv + ct).decode()


def decrypt_body(b64: str, share_key: str) -> str:
    raw = base64.b64decode(b64)
    return _aes_cbc_decrypt(bytes.fromhex(share_key)[:16], raw[:16], raw[16:]).decode()


def sign_request(share_key: str, ts: str, once: str, enc_body: str | None = None) -> str:
    parts = [ts, once] + ([enc_body] if enc_body else [])
    return hmac.new(share_key[:32].encode(), "+".join(parts).encode(), hashlib.sha256).hexdigest()


def signed_headers(key_ident: str, share_key: str, enc_body: str) -> dict[str, str]:
    ts, once = str(int(time.time())), gen_id()
    return {
        "x-encryption-info": "algo_ecdh",
        "x-key-ident": key_ident,
        "x-request-ts": ts,
        "x-request-once": once,
        "x-signature": sign_request(share_key, ts, once, enc_body),
    }


def prepare_key_exchange(local_key_hex: str = MEGA_LOCAL_KEY_HEX) -> dict[str, Any]:
    """Build a key-exchange request (private key, ident, JSON body, headers)."""
    local_key = bytes.fromhex(local_key_hex)
    key = ec.generate_private_key(ec.SECP256R1())
    iv = os.urandom(16)
    enc_pub = base64.b64encode(iv + _aes_cbc_encrypt(local_key, iv, _public_hex(key).encode())).decode()
    ts, once, ident = str(int(time.time())), gen_id(), gen_id()
    sig = hmac.new(local_key_hex.encode(), f"{ts}+{once}+{enc_pub}".encode(), hashlib.sha256).hexdigest()
    return {
        "key": key,
        "local_key": local_key,
        "ident": ident,
        "body": {"client_public_key": enc_pub},
        "headers": {
            "x-encryption-info": "algo_ecdh",
            "x-replay-info": "replay",
            "x-key-ident": ident,
            "x-request-ts": ts,
            "x-request-once": once,
            "x-signature": sig,
        },
    }


def finish_key_exchange(prep: dict[str, Any], server_public_b64: str) -> str:
    """Decrypt the server public key and derive the shareKey (32 hex chars)."""
    blob = base64.b64decode(server_public_b64)
    server_hex = _aes_cbc_decrypt(prep["local_key"], blob[:16], blob[16:]).decode()
    shared = prep["key"].exchange(ec.ECDH(), _load_public(server_hex))
    return shared.hex().rjust(64, "0")[:32]
