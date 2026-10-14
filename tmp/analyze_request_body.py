#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分析请求 body（get.txt）的解密可行性。

结论预期：
  - 请求的 key 用「服务端公钥」加密 → 客户端私钥解不开
  - 本脚本验证这一点，并识别哪把扫到的公钥是服务端公钥候选
  - 给出可落地的替代抓明文路径（内存扫 Fernet / 构造请求）
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

ROOT = Path(__file__).resolve().parents[1]
TMP = Path(__file__).resolve().parent
EXT = TMP / "captured" / "pem_ext"
KEYS = TMP / "captured" / "keys_clean"
GET_TXT = ROOT / "get.txt"
OUT = TMP / "captured" / "request_analysis.json"


def b64(s: str) -> bytes:
    s = s.strip()
    pad = "=" * ((4 - len(s) % 4) % 4)
    for fn in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return fn(s + pad)
        except Exception:
            continue
    return base64.b64decode(s.replace("-", "+").replace("_", "/") + pad)


def n_fp(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return hashlib.sha256(raw).hexdigest()[:16]


def extract_envelope(text: str) -> dict:
    m = re.search(r'\{\s*"data"\s*:.*?"key"\s*:.*?\}', text, re.S)
    if not m:
        raise ValueError("no envelope in get.txt")
    return json.loads(m.group(0))


def try_decrypt_rsa(priv, blob: bytes):
    pads = [
        ("OAEP-SHA256", padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)),
        ("PKCS1v15", padding.PKCS1v15()),
        ("OAEP-SHA1", padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None)),
    ]
    for name, pad in pads:
        try:
            return name, priv.decrypt(blob, pad)
        except Exception:
            continue
    return None


def try_fernet(fkey: bytes, token: bytes):
    cands = [fkey]
    if len(fkey) == 32:
        cands.append(base64.urlsafe_b64encode(fkey))
    for fk in cands:
        try:
            return Fernet(fk).decrypt(token)
        except Exception:
            continue
    return None


def load_all_privates():
    items = []
    paths = list(KEYS.glob("*private*.pem")) + list(EXT.glob("*PRIVATE*.pem")) + list(EXT.glob("*PRIVATE_KEY*.pem"))
    # also demo
    for extra in [
        ROOT / "demo" / "private_key.pem",
        ROOT / "demo" / "tmpvzd2agdz.pem",
    ]:
        if extra.exists():
            paths.append(extra)
    seen = set()
    for path in paths:
        raw = path.read_bytes()
        h = hashlib.sha256(raw).hexdigest()
        if h in seen:
            continue
        seen.add(h)
        try:
            priv = serialization.load_pem_private_key(raw, password=None)
        except Exception:
            continue
        pubn = priv.private_numbers().public_numbers.n
        items.append((path, priv, priv.key_size, n_fp(pubn), pubn))
    return items


def load_all_publics():
    items = []
    paths = list(EXT.glob("*PUBLIC*.pem")) + list(KEYS.glob("*public*.pem")) + list(KEYS.glob("server_pub.pem"))
    demo_pub = ROOT / "demo" / "public_key.pem"
    if demo_pub.exists():
        paths.append(demo_pub)
    seen = set()
    for path in paths:
        try:
            pub = serialization.load_pem_public_key(path.read_bytes())
        except Exception:
            continue
        n = pub.public_numbers().n
        fp = n_fp(n)
        if fp in seen:
            continue
        seen.add(fp)
        items.append((path, pub, pub.key_size, fp, n))
    return items


def main() -> int:
    report = {"steps": [], "conclusion": {}}

    if not GET_TXT.exists():
        print("[-] missing get.txt")
        return 1

    env = extract_envelope(GET_TXT.read_text(encoding="utf-8", errors="replace"))
    key_ct = b64(env["key"])
    data = b64(env["data"])
    print(f"[*] get.txt key_ct={len(key_ct)}B data={len(data)}B prefix={data[:16]!r}")
    report["envelope"] = {
        "key_len": len(key_ct),
        "data_len": len(data),
        "fernet_ascii": data.startswith(b"gAAAAA"),
    }

    # Fernet timestamp
    if data.startswith(b"gAAAAA") and len(data) > 25:
        try:
            # Fernet token: version(1) + timestamp(8) after urlsafe decode of whole token
            raw_tok = data  # already ascii token; Fernet uses the ascii form
            # decode inner: cryptography Fernet._get_unverified_token_data
            from cryptography.fernet import Fernet as F
            # manual: urlsafe decode without verify
            pad = b"=" * ((4 - len(data) % 4) % 4)
            inner = base64.urlsafe_b64decode(data + pad)
            import struct, datetime
            ts = struct.unpack(">Q", inner[1:9])[0]
            print(f"[*] Fernet timestamp UTC: {datetime.datetime.utcfromtimestamp(ts).isoformat()}Z")
            report["fernet_ts"] = datetime.datetime.utcfromtimestamp(ts).isoformat() + "Z"
        except Exception as e:
            print(f"[*] fernet ts parse skip: {e}")

    print("\n== 1) 用所有已知私钥尝试解密请求 key ==")
    privs = load_all_privates()
    decrypted = None
    for path, priv, bits, fp, n in privs:
        hit = try_decrypt_rsa(priv, key_ct)
        status = "OK" if hit else "fail"
        print(f"  [{status}] {bits}bit fp={fp} {path.name}")
        report["steps"].append({"priv": str(path), "bits": bits, "fp": fp, "rsa": bool(hit)})
        if hit:
            pad_name, fkey = hit
            print(f"       RSA {pad_name} -> fkey={fkey[:48]!r}")
            pt = try_fernet(fkey, data)
            if pt:
                print(f"       FERNET OK: {pt[:200]!r}")
                decrypted = pt
                report["decrypted"] = pt.decode("utf-8", "replace")
            else:
                print("       Fernet fail")

    print("\n== 2) 公钥与私钥配对关系 ==")
    pubs = load_all_publics()
    priv_ns = {n_fp(n): (path, bits) for path, priv, bits, fp, n in privs for fp in [n_fp(n)]}
    # fix: use n directly
    priv_by_n = {}
    for path, priv, bits, fp, n in privs:
        priv_by_n[n] = (path, bits, fp)

    body_priv_n = None
    for path, priv, bits, fp, n in privs:
        if "body_rsa2048" in path.name or (bits == 2048 and "14_RSA_PRIVATE" in path.name):
            body_priv_n = n
            print(f"  body client priv fp={fp} bits={bits}")

    server_candidates = []
    for path, pub, bits, fp, n in pubs:
        has_priv = n in priv_by_n
        tag = "HAS_PRIV(client-side)" if has_priv else "NO_PRIV → 可能是服务端/外部公钥"
        print(f"  pub {bits}bit fp={fp} {path.name} | {tag}")
        if bits == 2048 and not has_priv:
            server_candidates.append({"path": str(path), "fp": fp})
        report["steps"].append({"pub": str(path), "fp": fp, "bits": bits, "has_matching_priv": has_priv})

    print(f"\n[*] 服务端公钥候选（2048 且本地无对应私钥）: {len(server_candidates)}")
    for c in server_candidates:
        print(f"    fp={c['fp']} {c['path']}")

    # marked server_pub
    sp = KEYS / "server_pub.pem"
    if sp.exists():
        pub = serialization.load_pem_public_key(sp.read_bytes())
        print(f"[*] keys_clean/server_pub.pem fp={n_fp(pub.public_numbers().n)}")
        meta = KEYS / "server_pub_meta.json"
        if meta.exists():
            print(f"[*] meta: {meta.read_text(encoding='utf-8').strip()}")

    print("\n== 3) 用服务端公钥「加密」探测（验证 OAEP 可封装 44B Fernet key） ==")
    test_key = Fernet.generate_key()
    for c in server_candidates[:5]:
        pub = serialization.load_pem_public_key(Path(c["path"]).read_bytes())
        for pad_name, pad in [
            ("OAEP-SHA256", padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)),
            ("PKCS1v15", padding.PKCS1v15()),
        ]:
            try:
                ct = pub.encrypt(test_key, pad)
                print(f"  fp={c['fp']} {pad_name} encrypt OK ct_len={len(ct)}")
            except Exception as e:
                print(f"  fp={c['fp']} {pad_name} encrypt FAIL {type(e).__name__}")

    print("\n== 4) 结论 ==")
    if decrypted:
        print("[+] 请求已被某把私钥解开（意外！）")
        report["conclusion"]["decryptable"] = True
    else:
        print("[-] 所有已知私钥均无法解密 get.txt 的 key")
        print("    → 请求方向：Fernet_key 被【服务端公钥】RSA 加密")
        print("    → 解密请求明文需要：")
        print("       A) 服务端 RSA 私钥（客户端通常没有）")
        print("       B) 在客户端加密前截获 Fernet key / 明文（内存或 Hook）")
        print("       C) 自己持有服务端公钥后【重新构造】新请求（不必解密旧 get.txt）")
        report["conclusion"] = {
            "decryptable_with_known_keys": False,
            "reason": "request key encrypted to server public key",
            "server_pub_candidates": server_candidates,
            "practical_paths": [
                "live_capture_fernet_before_rsa",
                "rebuild_request_with_server_pub",
                "obtain_server_private (not in client)",
            ],
        }

    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[+] report -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
