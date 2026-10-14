#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Collect static facts for the analysis report (read-only)."""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
import re
import struct
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate

ROOT = Path(__file__).resolve().parents[1]
EXT = ROOT / "S2TD_Converter_v.2.2_CN_MT.exe_extracted"
PYZ = EXT / "PYZ-00.pyz_extracted"
DEMO = ROOT / "demo"
OUT = Path(__file__).with_name("analysis_facts.txt")


def b64(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(s + pad)
    except Exception:
        return base64.b64decode(s.replace("-", "+").replace("_", "/") + pad)


def main() -> None:
    lines: list[str] = []

    # --- Fernet token ---
    raw = (ROOT / "get.txt").read_text(encoding="utf-8")
    body = json.loads(raw.split("\n\n", 1)[1].strip())
    # Outer JSON fields are base64. data outer-decodes to Fernet token ASCII (gAAAAA...).
    data_outer = b64(body["data"])
    key_ct = b64(body["key"])
    lines.append("=== get.txt body ===")
    lines.append(f"data_outer_prefix={data_outer[:16]!r} fernet_ascii={data_outer.startswith(b'gAAAAA')}")
    lines.append(f"key_ct_len={len(key_ct)} (RSA-2048 ciphertext size)")
    if data_outer.startswith(b"gAAAAA"):
        token = b64(data_outer.decode("ascii"))
        ts = int.from_bytes(token[1:9], "big")
        try:
            ts_s = dt.datetime.utcfromtimestamp(ts).isoformat() + "Z"
        except (OSError, OverflowError, ValueError):
            ts_s = f"<invalid {ts}>"
        lines.append(
            f"Fernet version=0x{token[0]:02x} ts={ts} utc={ts_s} token_bin_len={len(token)}"
        )

    # --- cert ---
    cert = load_pem_x509_certificate((DEMO / "cert.pem").read_bytes())
    lines.append("=== mTLS client cert ===")
    lines.append(f"subject={cert.subject.rfc4514_string()}")
    lines.append(f"issuer={cert.issuer.rfc4514_string()}")
    lines.append(f"serial={format(cert.serial_number, 'X')}")
    lines.append(f"sha1={cert.fingerprint(hashes.SHA1()).hex().upper()}")
    lines.append(f"pubkey_bits={cert.public_key().key_size}")
    lines.append(f"validity={cert.not_valid_before} .. {cert.not_valid_after}")

    tls_priv = serialization.load_pem_private_key(
        (DEMO / "tmpvzd2agdz.pem").read_bytes(), password=None
    )
    lines.append(
        f"tmpvzd2agdz.pem matches cert: {tls_priv.public_key().public_numbers() == cert.public_key().public_numbers()}"
    )

    # --- rsa_test key ---
    text = (DEMO / "rsa_test.py").read_text(encoding="utf-8")
    m = re.search(r'PRIVATE_KEY_PEM\s*=\s*"""(.*?)"""', text, re.S)
    assert m
    app_priv = serialization.load_pem_private_key(m.group(1).encode(), password=None)
    lines.append("=== rsa_test hardcoded RSA ===")
    lines.append(f"bits={app_priv.key_size}")
    pem_priv = serialization.load_pem_private_key(
        (DEMO / "private_key.pem").read_bytes(), password=None
    )
    lines.append(
        f"private_key.pem same as rsa_test: {pem_priv.public_key().public_numbers().n == app_priv.public_key().public_numbers().n}"
    )

    # --- pyarmor modules ---
    lines.append("=== Pyarmor-protected app modules ===")
    armored = []
    for f in sorted(os.listdir(PYZ)):
        if not f.endswith(".pyc"):
            continue
        p = PYZ / f
        if p.stat().st_size > 5_000_000:
            continue
        data = p.read_bytes()
        if b"PYARMOR" in data:
            armored.append((p.stat().st_size, f))
    for sz, f in armored:
        lines.append(f"  {sz:8d}  {f}")

    # Session entry path leak
    sess = (EXT / "Session.2.TData_CN_MT").read_bytes()
    for s in re.findall(rb"[\x20-\x7e]{8,120}", sess):
        t = s.decode()
        if "Session" in t or "pyarmor" in t.lower() or "dist" in t:
            lines.append(f"Session string: {t}")

    # header
    idx = sess.find(b"PYARMOR")
    hdr = sess[idx : idx + 32]
    lines.append(f"Session PYARMOR header hex={hdr.hex()}")
    lines.append(f"Session PYARMOR header raw={hdr!r}")
    # bytes: PYARMOR + 00 00 + pyver(2) ...
    # Observed: PYARMOR\x00\x00\x03\n  => Python 3.10
    lines.append(f"python_major={hdr[9]} python_minor={hdr[10]}")

    # _pytransform
    dll = (EXT / "_pytransform.dll").read_bytes()
    lines.append("=== _pytransform.dll ===")
    lines.append(f"size={len(dll)} pyarmor-vax={dll.find(b'pyarmor-vax')} PY00={dll.find(b'PY00')}")
    interesting = []
    for s in set(re.findall(rb"[\x20-\x7e]{6,80}", dll)):
        t = s.decode()
        if any(k in t.lower() for k in ("pyarmor", "version", "protect", "license", "vax")):
            interesting.append(t)
    for t in sorted(interesting)[:40]:
        lines.append(f"  dllstr: {t}")

    # stack
    lines.append("=== Tech stack indicators ===")
    for name in [
        "python310.dll",
        "libssl-1_1.dll",
        "libcrypto-1_1.dll",
        "_pytransform.dll",
        "tgcrypto.cp310-win_amd64.pyd",
        "PyQt5",
    ]:
        p = EXT / name
        lines.append(f"  {name}: exists={p.exists()}")

    # license key format
    lic = (ROOT / "S2TD_LicenseKey.txt").read_text(encoding="utf-8").strip()
    lines.append(f"=== LicenseKey === {lic}")

    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(OUT.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
