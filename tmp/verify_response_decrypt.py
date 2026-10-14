#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
用扫到的 body RSA-2048 私钥验证：能否正确解密服务端响应。

1) 解密已保存的 tmp/latest_body.json
2) 现场 mTLS 拉一条新响应再解密（确认密钥对当前服务端仍有效）

用法:
  python tmp/verify_response_decrypt.py
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

ROOT = Path(__file__).resolve().parents[1]
TMP = Path(__file__).resolve().parent
KEYS = TMP / "captured" / "keys_clean"
OUT = TMP / "captured"

PRIV = KEYS / "body_rsa2048_private.pem"
MTLS_CERT = KEYS / "mtls_client_cert.pem"
MTLS_KEY = KEYS / "mtls_rsa4096_private.pem"
# fallback demo paths
if not MTLS_CERT.exists():
    MTLS_CERT = ROOT / "demo" / "cert.pem"
if not MTLS_KEY.exists():
    MTLS_KEY = ROOT / "demo" / "tmpvzd2agdz.pem"

LATEST = TMP / "latest_body.json"
URL = "https://lic.megacave.com/api/v2/get-csrf-token"


def b64decode_any(s: str) -> bytes:
    s = s.strip()
    pad = "=" * ((4 - len(s) % 4) % 4)
    for fn in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return fn(s + pad)
        except Exception:
            continue
    return base64.b64decode(s.replace("-", "+").replace("_", "/") + pad)


def decrypt_envelope(priv, obj: dict) -> tuple[str, bytes, bytes]:
    """Return (rsa_pad_name, fernet_key, plaintext)."""
    key_ct = b64decode_any(obj["key"])
    data = b64decode_any(obj["data"])
    if len(key_ct) != 256:
        raise ValueError(f"unexpected RSA ciphertext length: {len(key_ct)}")

    pads = [
        (
            "OAEP-SHA256",
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        ),
        ("PKCS1v15", padding.PKCS1v15()),
        (
            "OAEP-SHA1",
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        ),
    ]
    last_err = None
    for name, pad in pads:
        try:
            fkey = priv.decrypt(key_ct, pad)
            break
        except Exception as e:
            last_err = e
            fkey = None
            name = None
    else:
        raise RuntimeError(f"RSA decrypt failed: {last_err}")

    assert name and fkey is not None
    token = data if data.startswith(b"gAAAAA") else obj["data"].encode()
    # Fernet key is typically urlsafe-b64 of 32 bytes (44 ascii chars)
    try:
        pt = Fernet(fkey).decrypt(token)
    except Exception:
        if len(fkey) == 32:
            pt = Fernet(base64.urlsafe_b64encode(fkey)).decrypt(token)
        else:
            raise
    return name, fkey, pt


def show_result(label: str, pad: str, fkey: bytes, pt: bytes, save_name: str) -> None:
    print(f"[+] {label}")
    print(f"    RSA padding : {pad}")
    print(f"    Fernet key  : {fkey!r}")
    print(f"    plaintext   : {pt.decode('utf-8', errors='replace')}")
    try:
        parsed = json.loads(pt)
        print(f"    as JSON     : {json.dumps(parsed, ensure_ascii=False)}")
    except Exception:
        pass
    out = OUT / save_name
    out.write_bytes(pt)
    print(f"    saved       : {out}")


def main() -> int:
    if not PRIV.exists():
        print(f"[-] missing {PRIV}")
        print("    先运行: python tmp/scan_process_pem.py -n S2TD_Converter_v.2.5_EN.exe")
        print("           python tmp/try_scanned_keys.py")
        return 1

    priv = serialization.load_pem_private_key(PRIV.read_bytes(), password=None)
    print(f"[*] body private key: {PRIV} ({priv.key_size} bit)")
    print(f"[*] mTLS cert/key   : {MTLS_CERT.name} / {MTLS_KEY.name}")
    ok = 0
    fail = 0

    # --- 1) saved response ---
    print("\n== 1) 解密已保存响应 latest_body.json ==")
    if not LATEST.exists():
        print(f"[-] missing {LATEST}")
        fail += 1
    else:
        obj = json.loads(LATEST.read_text(encoding="utf-8"))
        try:
            pad, fkey, pt = decrypt_envelope(priv, obj)
            show_result("saved response OK", pad, fkey, pt, "verify_saved_response.json")
            ok += 1
        except Exception as e:
            print(f"[-] saved response FAIL: {type(e).__name__}: {e}")
            fail += 1

    # --- 2) live response ---
    print("\n== 2) 现场拉取新响应并解密 ==")
    try:
        import requests
        from urllib3.exceptions import InsecureRequestWarning

        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    except ImportError:
        print("[-] pip install requests")
        fail += 1
    else:
        if not MTLS_CERT.exists() or not MTLS_KEY.exists():
            print("[-] mTLS materials missing, skip live test")
            fail += 1
        else:
            try:
                r = requests.get(
                    URL,
                    cert=(str(MTLS_CERT), str(MTLS_KEY)),
                    verify=False,
                    timeout=30,
                    headers={"Accept": "application/json", "Content-Type": "application/json"},
                )
                print(f"[*] HTTP {r.status_code}")
                print(f"[*] body preview: {r.text[:180]}...")
                live_path = OUT / "live_response_envelope.json"
                try:
                    env = r.json()
                except Exception:
                    print("[-] response is not JSON")
                    fail += 1
                else:
                    live_path.write_text(
                        json.dumps(
                            {
                                **env,
                                "http_status": r.status_code,
                                "source": "verify_response_decrypt.py live",
                            },
                            ensure_ascii=False,
                            indent=2,
                        ),
                        encoding="utf-8",
                    )
                    print(f"[*] saved envelope: {live_path}")
                    if "data" in env and "key" in env:
                        pad, fkey, pt = decrypt_envelope(priv, env)
                        show_result("live response OK", pad, fkey, pt, "verify_live_response.json")
                        ok += 1
                    else:
                        print(f"[-] no data/key fields: {list(env)[:20]}")
                        fail += 1
            except Exception as e:
                print(f"[-] live request/decrypt FAIL: {type(e).__name__}: {e}")
                fail += 1

    print("\n== 结论 ==")
    print(f"通过 {ok} / 失败 {fail}")
    if ok and not fail:
        print("[+] 密钥正确：可稳定解密服务端响应（RSA-OAEP-SHA256 + Fernet）")
        return 0
    if ok:
        print("[*] 部分通过：私钥至少能解已保存响应；现场失败可能是网络/证书问题")
        return 0
    print("[-] 验证失败")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
