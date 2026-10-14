#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
演示请求 body 加密封装（无法解密旧 get.txt，但可按同方案构造新请求）。

  python tmp/demo_request_seal.py
  python tmp/demo_request_seal.py --plaintext "{\"csrf\":\"demo\"}"
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TMP = Path(__file__).resolve().parent
sys.path.insert(0, str(TMP))

from body_crypto import load_private, load_public, open_json, seal  # noqa: E402

KEYS = TMP / "captured" / "keys_clean"
SERVER_PUB = KEYS / "server_pub.pem"
CLIENT_PRIV = KEYS / "body_rsa2048_private.pem"
GET_TXT = ROOT / "get.txt"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--plaintext", default='{"ping":1,"note":"request-seal-demo"}')
    args = ap.parse_args()

    if not SERVER_PUB.exists() or not CLIENT_PRIV.exists():
        print("[-] missing keys_clean/server_pub.pem or body_rsa2048_private.pem")
        return 1

    server_pub = load_public(SERVER_PUB)
    client_priv = load_private(CLIENT_PRIV)

    print("== 旧 get.txt：客户端私钥无法解开（需服务端私钥）==")
    if GET_TXT.exists():
        raw = GET_TXT.read_text(encoding="utf-8", errors="replace")
        body = json.loads(raw.split("\n\n", 1)[1].strip())
        try:
            open_json(body, client_priv)
            print("[!] unexpected: decrypted get.txt")
        except Exception as e:
            print(f"[-] decrypt get.txt FAIL (expected): {type(e).__name__}")

    print("\n== 构造新请求 envelope（服务端公钥 OAEP-SHA256）==")
    try:
        pt = json.loads(args.plaintext)
    except Exception:
        pt = args.plaintext
    env = seal(pt, server_pub, rsa_padding="oaep")
    print(json.dumps(env, indent=2)[:400], "...")
    out = TMP / "captured" / "demo_request_envelope.json"
    out.write_text(json.dumps({"plaintext": pt, "envelope": env}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] saved {out}")

    print("\n== 说明 ==")
    print("请求解密：只有持有 server_pub 对应【私钥】的一方能解。")
    print("客户端侧可行路径：加密前截获明文，或直接用 seal() 发新请求。")
    print("服务端响应：用 client_priv + open_json() 解（已验证）。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
