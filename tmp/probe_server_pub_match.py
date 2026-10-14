#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模拟发送加密请求，探测哪把「服务端公钥」与线上匹配。

判定：
  - 能解开响应，且明文是业务层错误（如缺 token）→ 公钥+padding 很可能正确
  - 明文像解密失败 / 无法理解 → 公钥或 padding 不对
  - 响应无法用客户端私钥解开 → 其它问题

用法:
  python tmp/probe_server_pub_match.py
  python tmp/probe_server_pub_match.py --quick   # 只测 server_pub.pem
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

import requests
from urllib3.exceptions import InsecureRequestWarning

ROOT = Path(__file__).resolve().parents[1]
TMP = Path(__file__).resolve().parent
sys.path.insert(0, str(TMP))

from body_crypto import load_private, load_public, open_json, seal  # noqa: E402
from cryptography.hazmat.primitives import serialization

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

KEYS = TMP / "captured" / "keys_clean"
EXT = TMP / "captured" / "pem_ext"
OUT_DIR = TMP / "captured" / "pub_probe"
URL = "https://lic.megacave.com/api/v2/get-csrf-token"

MTLS_CERT = KEYS / "mtls_client_cert.pem"
MTLS_KEY = KEYS / "mtls_rsa4096_private.pem"
CLIENT_PRIV = KEYS / "body_rsa2048_private.pem"
if not MTLS_CERT.exists():
    MTLS_CERT = ROOT / "demo" / "cert.pem"
if not MTLS_KEY.exists():
    MTLS_KEY = ROOT / "demo" / "tmpvzd2agdz.pem"


def n_fp(pub) -> str:
    n = pub.public_numbers().n
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return hashlib.sha256(raw).hexdigest()[:16]


def iter_candidate_pubs(quick: bool):
    seen = set()
    paths = []
    if (KEYS / "server_pub.pem").exists():
        paths.append(KEYS / "server_pub.pem")
    if not quick:
        paths.extend(sorted(EXT.glob("*PUBLIC*.pem")))
        paths.extend(sorted(EXT.glob("*PUBLIC_KEY*.pem")))
    for path in paths:
        try:
            pub = load_public(path)
        except Exception:
            continue
        if pub.key_size != 2048:
            continue
        fp = n_fp(pub)
        if fp in seen:
            continue
        seen.add(fp)
        yield path, pub, fp


def score_plain(plain) -> tuple[int, str]:
    """Higher = more likely crypto matched."""
    if plain is None:
        return 0, "no_plain"
    text = plain if isinstance(plain, str) else json.dumps(plain, ensure_ascii=False)
    low = text.lower()
    # strong signals that server decrypted our body and hit app logic
    if "'token'" in text or '"token"' in low or "token" in low and "missing" in low:
        return 100, "app_missing_token"
    if "csrf" in low and ("token" in low or "key" in low):
        return 90, "app_csrf_related"
    if "unsupported media type" in low:
        return 20, "content_type"  # may not have read body
    if "bad request" in low and "could not understand" in low:
        return 15, "bad_request_generic"
    if any(x in low for x in ("decrypt", "padding", "incorrect", "invalid key", "cipher")):
        return 5, "crypto_error_hint"
    if "message" in (plain if isinstance(plain, dict) else {}):
        return 40, "app_message"
    return 10, "other"


def send_once(pub, pad: str, plaintext: dict, method: str = "GET") -> dict:
    env = seal(plaintext, pub, rsa_padding=pad)
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) S2TD-Probe",
    }
    kwargs = dict(
        url=URL,
        headers=headers,
        cert=(str(MTLS_CERT), str(MTLS_KEY)),
        verify=False,
        timeout=30,
        data=json.dumps(env, separators=(",", ":")),
    )
    if method.upper() == "GET":
        # match get.txt style: GET with body
        r = requests.request("GET", **kwargs)
    else:
        r = requests.post(**kwargs)

    result = {
        "http": r.status_code,
        "cookie": r.headers.get("Set-Cookie", ""),
        "raw_preview": r.text[:240],
    }
    try:
        resp_env = r.json()
    except Exception:
        result["plain"] = None
        result["decrypt"] = "not_json"
        return result

    result["has_envelope"] = "data" in resp_env and "key" in resp_env
    if result["has_envelope"]:
        try:
            priv = load_private(CLIENT_PRIV)
            plain = open_json(resp_env, priv)
            result["plain"] = plain
            result["decrypt"] = "ok"
        except Exception as e:
            result["plain"] = None
            result["decrypt"] = f"fail:{type(e).__name__}"
    else:
        result["plain"] = resp_env
        result["decrypt"] = "no_envelope"
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="only test keys_clean/server_pub.pem")
    ap.add_argument("--limit", type=int, default=0, help="max public keys (0=all)")
    args = ap.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    if not CLIENT_PRIV.exists():
        print(f"[-] missing {CLIENT_PRIV}")
        return 1

    payloads = [
        {"token": ""},
        {"token": "test"},
        {},
    ]
    pads = ["oaep", "pkcs1"]
    methods = ["GET", "POST"]

    cands = list(iter_candidate_pubs(args.quick))
    if args.limit:
        cands = cands[: args.limit]
    print(f"[*] candidates={len(cands)} mTLS={MTLS_CERT.name} url={URL}")

    rows = []
    best = None
    for path, pub, fp in cands:
        for pad in pads:
            for method in methods:
                for payload in payloads:
                    label = f"fp={fp} pad={pad} {method} body={json.dumps(payload, ensure_ascii=False)}"
                    print(f"[>] {label} <- {path.name}")
                    try:
                        res = send_once(pub, pad, payload, method=method)
                    except Exception as e:
                        print(f"    ERR {type(e).__name__}: {e}")
                        rows.append({"fp": fp, "pad": pad, "method": method, "payload": payload, "error": str(e)})
                        continue
                    sc, reason = score_plain(res.get("plain"))
                    row = {
                        "fp": fp,
                        "path": str(path),
                        "pad": pad,
                        "method": method,
                        "payload": payload,
                        "http": res["http"],
                        "decrypt": res.get("decrypt"),
                        "score": sc,
                        "reason": reason,
                        "plain": res.get("plain"),
                    }
                    rows.append(row)
                    plain_s = json.dumps(res.get("plain"), ensure_ascii=False) if res.get("plain") is not None else None
                    print(f"    HTTP {res['http']} decrypt={res.get('decrypt')} score={sc} ({reason}) plain={plain_s}")
                    if best is None or sc > best["score"]:
                        best = row
                    time.sleep(0.35)  # be polite

    out = OUT_DIR / "probe_results.json"
    out.write_text(json.dumps({"best": best, "rows": rows}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[+] saved {out}")

    print("\n== 匹配结论 ==")
    if not best:
        print("[-] 无有效结果")
        return 1
    print(f"best score={best['score']} reason={best['reason']}")
    print(f"  fp={best['fp']} pad={best['pad']} method={best['method']}")
    print(f"  payload={best['payload']}")
    print(f"  plain={best['plain']}")
    print(f"  path={best['path']}")

    # summarize by fp+pad max score
    summary = {}
    for r in rows:
        if "score" not in r:
            continue
        k = (r["fp"], r["pad"])
        summary[k] = max(summary.get(k, -1), r["score"])
    print("\n按 fp+pad 最高分:")
    for (fp, pad), sc in sorted(summary.items(), key=lambda x: -x[1]):
        mark = " <== 可疑匹配" if sc >= 90 else ""
        print(f"  {fp} {pad}: {sc}{mark}")

    if best["score"] >= 90:
        # refresh server_pub if needed
        src = Path(best["path"])
        dst = KEYS / "server_pub.pem"
        if src.resolve() != dst.resolve():
            dst.write_bytes(src.read_bytes())
            print(f"[+] updated {dst}")
        meta = {
            "fp": best["fp"],
            "pad": best["pad"],
            "method": best["method"],
            "payload": best["payload"],
            "score": best["score"],
            "reason": best["reason"],
            "plain": best["plain"],
            "path": best["path"],
            "verified": True,
        }
        (KEYS / "server_pub_meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[+] updated {KEYS / 'server_pub_meta.json'}")
        print("[+] 请求加密公钥匹配：服务端能解密我们的 body（业务层已读到字段）")
        return 0

    print("[*] 未出现强匹配（score>=90）。若最高分仍较低，可能公钥集不全或接口字段不同。")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
