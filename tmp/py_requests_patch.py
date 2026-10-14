# -*- coding: utf-8 -*-
"""
注入到目标进程：monkeypatch requests.Session.send + Fernet.encrypt。

由 Frida 通过 PyRun_SimpleString / exec 加载。
只 Hook Session.send（最终 PreparedRequest，含完整 headers），避免包装
Session.request 干扰业务发包。
"""

import json
import os
import sys
import threading
time = __import__("time")
traceback = __import__("traceback")
from datetime import datetime, timezone

# Frida exec 时可能没有 __file__
_BASE = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()
LOG_PATH = os.environ.get(
    "S2TD_HTTP_CAPTURE_LOG",
    os.path.join(_BASE, "captured", "http_capture", "requests.jsonl"),
)


def _ensure_dir():
    d = os.path.dirname(LOG_PATH)
    if d and not os.path.isdir(d):
        try:
            os.makedirs(d)
        except Exception:
            pass


def _log(obj):
    _ensure_dir()
    try:
        if "ts" not in obj:
            obj["ts"] = datetime.now(timezone.utc).isoformat()
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False, default=str) + "\n")
            f.flush()
    except Exception:
        pass


def _preview(body, limit=200000):
    if body is None:
        return None
    if isinstance(body, bytes):
        try:
            return body.decode("utf-8")
        except Exception:
            return {"hex": body[: min(len(body), 4096)].hex(), "len": len(body)}
    if isinstance(body, str):
        return body[:limit]
    try:
        return str(body)[:limit]
    except Exception:
        return "<unprintable>"


def _headers_dict(h):
    """安全转换 headers；单个值过长则截断（如 Cf-Client-Cert）。"""
    if not h:
        return {}
    out = {}
    try:
        items = h.items() if hasattr(h, "items") else dict(h).items()
        for k, v in items:
            ks = str(k)
            try:
                vs = v if isinstance(v, str) else (v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v))
            except Exception:
                vs = repr(v)
            # 完整保留业务头；超大头（证书）仍整段写入以便分析，但避免异常类型
            out[ks] = vs
    except Exception as e:
        out = {"_headers_error": str(e)}
    return out


def _patch_fernet():
    try:
        from cryptography.fernet import Fernet
    except Exception as e:
        _log({"channel": "error", "where": "import_fernet", "err": str(e)})
        return False

    if getattr(Fernet.encrypt, "_s2td_patched", False):
        return True

    real_encrypt = Fernet.encrypt
    real_gen = Fernet.generate_key
    real_decrypt = Fernet.decrypt

    def generate_key():
        k = real_gen()
        try:
            _log(
                {
                    "channel": "plaintext",
                    "phase": "fernet.generate_key",
                    "fernet_key": k.decode("ascii") if isinstance(k, bytes) else str(k),
                }
            )
        except Exception:
            pass
        return k

    def encrypt(self, data):
        try:
            if isinstance(data, bytes):
                try:
                    pt = data.decode("utf-8")
                except Exception:
                    pt = data.hex()
            else:
                pt = str(data)
            parsed = None
            try:
                parsed = json.loads(pt)
            except Exception:
                pass
            _log(
                {
                    "channel": "plaintext",
                    "phase": "fernet.encrypt",
                    "plaintext": pt[:200000],
                    "json": parsed,
                    "len": len(data) if hasattr(data, "__len__") else None,
                }
            )
            print("[S2TD-PLAINTEXT]", pt[:4000], flush=True)
        except Exception as e:
            _log({"channel": "error", "where": "fernet.encrypt.log", "err": str(e)})
        return real_encrypt(self, data)

    def decrypt(self, token, ttl=None):
        if ttl is None:
            out = real_decrypt(self, token)
        else:
            out = real_decrypt(self, token, ttl=ttl)
        try:
            if isinstance(out, bytes):
                try:
                    pt = out.decode("utf-8")
                except Exception:
                    pt = out.hex()
            else:
                pt = str(out)
            parsed = None
            try:
                parsed = json.loads(pt)
            except Exception:
                pass
            _log(
                {
                    "channel": "plaintext",
                    "phase": "fernet.decrypt",
                    "plaintext": pt[:200000],
                    "json": parsed,
                }
            )
        except Exception:
            pass
        return out

    generate_key._s2td_patched = True
    encrypt._s2td_patched = True
    decrypt._s2td_patched = True
    Fernet.generate_key = staticmethod(generate_key)
    Fernet.encrypt = encrypt
    Fernet.decrypt = decrypt
    _log({"channel": "status", "msg": "patched Fernet.encrypt/decrypt/generate_key"})
    return True


def _patch_requests():
    """只 Hook Session.send —— 这里能拿到最终 headers + body，且不干扰 request() 组装。"""
    import requests
    from requests.sessions import Session

    if getattr(Session.send, "_s2td_patched", False):
        return True

    real_send = Session.send

    def send(self, request, **kwargs):
        # 日志失败绝不能影响真实发送
        try:
            _log(
                {
                    "channel": "requests",
                    "phase": "request",
                    "method": getattr(request, "method", None),
                    "url": getattr(request, "url", None),
                    "headers": _headers_dict(getattr(request, "headers", None)),
                    "body": _preview(getattr(request, "body", None)),
                }
            )
        except Exception as e:
            _log({"channel": "error", "where": "request_log", "err": str(e)})

        resp = real_send(self, request, **kwargs)

        try:
            try:
                text = resp.text
            except Exception:
                text = _preview(getattr(resp, "content", None))
            _log(
                {
                    "channel": "requests",
                    "phase": "response",
                    "method": getattr(request, "method", None),
                    "url": getattr(request, "url", None),
                    "status": getattr(resp, "status_code", None),
                    "reason": getattr(resp, "reason", None),
                    "headers": _headers_dict(getattr(resp, "headers", None)),
                    "body": text[:200000] if isinstance(text, str) else text,
                }
            )
        except Exception as e:
            _log({"channel": "error", "where": "response_log", "err": str(e)})
        return resp

    send._s2td_patched = True
    Session.send = send
    _log({"channel": "status", "msg": "patched requests.Session.send (with headers)", "log": LOG_PATH})
    return True


def _try_patch_once():
    out = {"requests": False, "fernet": False}
    try:
        out["fernet"] = _patch_fernet()
    except Exception as e:
        _log({"channel": "error", "where": "fernet", "err": str(e), "tb": traceback.format_exc()})
    try:
        out["requests"] = _patch_requests()
    except Exception as e:
        _log({"channel": "error", "where": "requests", "err": str(e), "tb": traceback.format_exc()})
    return out


def install(poll_seconds=120.0):
    global LOG_PATH
    env_log = os.environ.get("S2TD_HTTP_CAPTURE_LOG")
    if env_log:
        LOG_PATH = env_log
    _ensure_dir()
    _log({"channel": "status", "msg": "py_requests_patch install start", "log": LOG_PATH, "pid": os.getpid()})

    def worker():
        deadline = time.time() + poll_seconds
        ok_fernet = False
        ok_req = False
        while time.time() < deadline:
            try:
                result = _try_patch_once()
                ok_fernet = ok_fernet or bool(result.get("fernet"))
                ok_req = ok_req or bool(result.get("requests"))
                if ok_fernet and ok_req:
                    _log({"channel": "status", "msg": "patch ok (fernet+requests)", "result": result})
                    return
                if ok_fernet or ok_req:
                    _log({"channel": "status", "msg": "patch partial", "result": result})
            except Exception as e:
                _log({"channel": "error", "where": "worker", "err": str(e)})
            time.sleep(0.4)
        _log({"channel": "status", "msg": "patch poll timeout", "fernet": ok_fernet, "requests": ok_req})

    threading.Thread(target=worker, name="s2td-http-patch", daemon=True).start()


install()
