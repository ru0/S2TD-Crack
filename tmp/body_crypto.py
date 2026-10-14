#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Body envelope: Fernet + RSA-OAEP-SHA256 (live megacave scheme)."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

OAEP_SHA256 = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)
PKCS1 = padding.PKCS1v15()


def b64decode_any(s: str) -> bytes:
    s = (s or "").strip()
    pad = "=" * ((4 - len(s) % 4) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder(s + pad)
        except Exception:
            continue
    return base64.b64decode(s.replace("-", "+").replace("_", "/") + pad)


def load_private(path: Path) -> RSAPrivateKey:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)  # type: ignore


def load_public(path: Path) -> RSAPublicKey:
    data = path.read_bytes()
    try:
        return serialization.load_pem_public_key(data)  # type: ignore
    except Exception:
        from cryptography import x509

        return x509.load_pem_x509_certificate(data).public_key()  # type: ignore


def seal(
    plaintext: bytes | str | dict[str, Any],
    server_public: RSAPublicKey,
    *,
    rsa_padding: str = "oaep",
) -> dict[str, str]:
    """Client → server: encrypt Fernet key with server public key."""
    if isinstance(plaintext, dict):
        raw = json.dumps(plaintext, separators=(",", ":"), ensure_ascii=False).encode()
    elif isinstance(plaintext, str):
        raw = plaintext.encode()
    else:
        raw = plaintext

    fkey = Fernet.generate_key()  # 44-byte urlsafe key
    token = Fernet(fkey).encrypt(raw)  # ascii gAAAAA...

    pad = OAEP_SHA256 if rsa_padding == "oaep" else PKCS1
    enc_key = server_public.encrypt(fkey, pad)

    return {
        # outer data: standard b64 of Fernet ASCII token (matches get.txt / responses)
        "data": base64.b64encode(token).decode("ascii"),
        # key: urlsafe b64 of RSA ciphertext (matches captures)
        "key": base64.urlsafe_b64encode(enc_key).decode("ascii"),
    }


def open_envelope(
    envelope: dict[str, str],
    client_private: RSAPrivateKey,
) -> bytes:
    """Server → client: decrypt key with client private, then Fernet."""
    key_blob = b64decode_any(envelope["key"])
    data_blob = b64decode_any(envelope["data"])

    fkey = None
    pad_used = None
    for name, pad in (("oaep", OAEP_SHA256), ("pkcs1", PKCS1)):
        try:
            fkey = client_private.decrypt(key_blob, pad)
            pad_used = name
            break
        except Exception:
            continue
    if fkey is None:
        raise ValueError("RSA decrypt failed (neither OAEP nor PKCS1)")

    # Fernet key is normally the 44-byte urlsafe string
    try:
        pt = Fernet(fkey).decrypt(data_blob)
    except Exception:
        if len(fkey) == 32:
            pt = Fernet(base64.urlsafe_b64encode(fkey)).decrypt(data_blob)
        else:
            raise
    # attach pad for debugging via attribute is awkward; caller can ignore
    _ = pad_used
    return pt


def open_json(envelope: dict[str, str], client_private: RSAPrivateKey) -> Any:
    pt = open_envelope(envelope, client_private)
    try:
        return json.loads(pt)
    except Exception:
        return pt
