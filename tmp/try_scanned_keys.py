#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate scanned PEMs and try decrypt known body envelopes."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
from pathlib import Path

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

ROOT = Path(__file__).resolve().parents[1]
TMP = Path(__file__).resolve().parent
EXT = TMP / "captured" / "pem_ext"
CLEAN = TMP / "captured" / "keys_clean"
GET_TXT = ROOT / "get.txt"
LATEST = TMP / "latest_body.json"


def b64decode_any(s: str) -> bytes:
    s = s.strip()
    pad = "=" * ((4 - len(s) % 4) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder(s + pad)
        except Exception:
            continue
    return base64.b64decode(s.replace("-", "+").replace("_", "/") + pad)


def n_fp(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return hashlib.sha256(raw).hexdigest()[:32]


def load_priv(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def try_rsa(priv, blob: bytes):
    pads = [
        ("PKCS1v15", padding.PKCS1v15()),
        (
            "OAEP-SHA256",
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        ),
        (
            "OAEP-SHA1",
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        ),
    ]
    for name, pad in pads:
        try:
            return name, priv.decrypt(blob, pad)
        except Exception:
            continue
    return None


def try_fernet(fkey: bytes, token: bytes):
    cands = []
    if len(fkey) == 44:
        cands.append(fkey)
    if len(fkey) == 32:
        cands.append(base64.urlsafe_b64encode(fkey))
    if len(fkey) > 32:
        cands.append(base64.urlsafe_b64encode(fkey[:32]))
    cands.append(fkey)
    for fk in cands:
        try:
            return Fernet(fk).decrypt(token)
        except Exception:
            continue
    return None


def extract_envelope(text: str) -> dict:
    text = text.strip()
    try:
        return json.loads(text)
    except Exception:
        pass
    m = re.search(r'\{\s*"data"\s*:.*?"key"\s*:.*?\}', text, re.S)
    if not m:
        m = re.search(r"\{.*\}", text, re.S)
    return json.loads(m.group(0))


def decrypt_envelope(label: str, obj: dict, keys: list[tuple[str, object]]):
    key_blob = b64decode_any(obj["key"])
    data_blob = b64decode_any(obj["data"])
    print(f"\n=== {label} key={len(key_blob)}B data={len(data_blob)}B start={data_blob[:16]!r}")
    for kname, priv in keys:
        hit = try_rsa(priv, key_blob)
        if not hit:
            print(f"  [{kname}] RSA decrypt fail")
            continue
        pad_name, fkey = hit
        print(f"  [{kname}] RSA {pad_name} OK fkey_len={len(fkey)} preview={fkey[:48]!r}")
        pt = try_fernet(fkey, data_blob)
        if pt is None and data_blob.startswith(b"gAAAAA"):
            pt = try_fernet(fkey, data_blob)
        if pt is not None:
            print(f"  [{kname}] FERNET OK -> {pt[:300]!r}")
            out = TMP / "captured" / f"decrypted_{label}.bin"
            out.write_bytes(pt)
            print(f"  saved {out}")
            return True
        print(f"  [{kname}] Fernet fail")
    return False


def main():
    CLEAN.mkdir(parents=True, exist_ok=True)
    p2048 = EXT / "20260801_132818_17964_14_RSA_PRIVATE_KEY.pem"
    p4096 = EXT / "20260801_132818_17964_13_PRIVATE_KEY.pem"
    cert_p = EXT / "20260801_132818_17964_15_CERTIFICATE.pem"

    k2048 = load_priv(p2048)
    k4096 = load_priv(p4096)
    cert = x509.load_pem_x509_certificate(cert_p.read_bytes())

    print("[+] RSA-2048 body candidate n_fp=", n_fp(k2048.private_numbers().public_numbers.n))
    print("[+] RSA-4096 mTLS candidate n_fp=", n_fp(k4096.private_numbers().public_numbers.n))
    print("[+] cert serial", format(cert.serial_number, "X"))
    print("[+] 4096 matches mTLS cert?", k4096.private_numbers().public_numbers.n == cert.public_key().public_numbers().n)

    # save clean copies
    shutil.copy(p2048, CLEAN / "body_rsa2048_private.pem")
    shutil.copy(p4096, CLEAN / "mtls_rsa4096_private.pem")
    shutil.copy(cert_p, CLEAN / "mtls_client_cert.pem")
    pub2048 = k2048.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (CLEAN / "body_rsa2048_public.pem").write_bytes(pub2048)
    print(f"[+] clean keys -> {CLEAN}")

    # compare demo
    demo = ROOT / "demo" / "private_key.pem"
    if demo.exists():
        d = load_priv(demo)
        same = d.private_numbers().public_numbers.n == k2048.private_numbers().public_numbers.n
        print("[+] demo/private_key.pem == scanned 2048?", same)

    keys = [("rsa2048", k2048), ("rsa4096", k4096)]

    if GET_TXT.exists():
        env = extract_envelope(GET_TXT.read_text(encoding="utf-8", errors="replace"))
        decrypt_envelope("get_txt", env, keys)
    if LATEST.exists():
        env = json.loads(LATEST.read_text(encoding="utf-8"))
        decrypt_envelope("latest_body", env, keys)

    # fernet hint from scan
    hint = EXT / "20260801_132818_17964_10_fernet_hint.txt"
    if hint.exists():
        print("\n[+] fernet hint:", hint.read_bytes()[:80])


if __name__ == "__main__":
    main()
