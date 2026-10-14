#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pretty-print latest http_capture requests.jsonl；响应 body 用客户端私钥解密。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

TMP = Path(__file__).resolve().parent
DIR = TMP / "captured" / "http_capture"
KEYS = TMP / "captured" / "keys_clean"
PRIV_PEM = KEYS / "body_rsa2048_private.pem"

sys.path.insert(0, str(TMP))
from body_crypto import load_private, open_envelope  # noqa: E402


def _parse_body(body):
    if body is None:
        return None
    if isinstance(body, dict):
        return body
    if isinstance(body, str):
        try:
            return json.loads(body)
        except Exception:
            return body
    return body


def _fmt(obj, limit: int = 4000) -> str:
    if isinstance(obj, (dict, list)):
        s = json.dumps(obj, ensure_ascii=False, indent=2)
    elif isinstance(obj, bytes):
        try:
            s = obj.decode("utf-8")
        except Exception:
            s = obj.hex()
    else:
        s = str(obj)
    return s if len(s) <= limit else s[:limit] + f"\n... ({len(s)} chars)"


def _decrypt_envelope(env: dict, priv) -> tuple[object | None, str | None]:
    if not isinstance(env, dict) or "data" not in env or "key" not in env:
        return None, "not envelope"
    try:
        pt = open_envelope(env, priv)
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"
    try:
        return json.loads(pt), None
    except Exception:
        try:
            return pt.decode("utf-8"), None
        except Exception:
            return pt, None


def main() -> int:
    files = sorted(DIR.glob("requests*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        print("[-] no requests_*.jsonl yet")
        return 1
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else files[0]
    print(f"[*] {path}")

    priv = None
    if PRIV_PEM.is_file():
        try:
            priv = load_private(PRIV_PEM)
            print(f"[*] decrypt key: {PRIV_PEM}")
        except Exception as e:
            print(f"[!] load private key failed: {e}")
    else:
        print(f"[!] missing {PRIV_PEM} — skip response decrypt")

    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not ln.strip():
            continue
        try:
            o = json.loads(ln)
        except Exception:
            print(ln[:200])
            continue
        ch = o.get("channel")
        phase = o.get("phase")
        if ch == "status" or ch == "error":
            print(f"[{ch}] {o.get('msg') or o}")
            continue
        if ch == "plaintext":
            print("\n**** PLAINTEXT ****")
            print(f"phase={phase}")
            if o.get("fernet_key"):
                print("fernet_key:", o["fernet_key"])
            if o.get("material"):
                print("rsa_material:", o["material"])
            if o.get("json") is not None:
                print(json.dumps(o["json"], ensure_ascii=False, indent=2))
            elif o.get("plaintext") is not None:
                print(o["plaintext"])
            continue
        if phase == "request":
            print("\n==== REQUEST ====")
            print(f"{o.get('method')} {o.get('url')}")
            hdrs = o.get("headers") or {}
            if hdrs:
                print("headers:", json.dumps(hdrs, ensure_ascii=False, indent=2)[:4000])
            body = _parse_body(o.get("body"))
            if body is not None:
                print("body(encrypted):", _fmt(body, 3000))
        elif phase == "response":
            print("---- RESPONSE ----")
            print(f"status={o.get('status')} {o.get('url')}")
            hdrs = o.get("headers") or {}
            if hdrs:
                print("headers:", json.dumps(hdrs, ensure_ascii=False, indent=2)[:1500])
            body = _parse_body(o.get("body"))
            print("body(encrypted):", _fmt(body, 3000))
            if priv is not None and isinstance(body, dict):
                plain, err = _decrypt_envelope(body, priv)
                if err:
                    print(f"body(decrypt): FAIL {err}")
                else:
                    print("body(decrypt):")
                    print(_fmt(plain, 8000))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
