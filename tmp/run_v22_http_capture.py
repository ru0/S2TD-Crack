#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S2TD_Converter_v.2.2_CN_MT.exe（PyInstaller）HTTP 完整抓包。

打开程序后会自动检查版本更新（无需点联网按钮）。
本脚本用 frida.spawn + child_gating，确保 Hook 到真正跑 Python 的子进程。

用法（无需管理员）:
  python tmp/run_v22_http_capture.py
  python tmp/run_v22_http_capture.py -e S2TD_Converter_v.2.2_CN_MT.exe

  # 若程序已打开（可能已错过更新请求）:
  python tmp/run_v22_http_capture.py -w S2TD_Converter_v.2.2_CN_MT.exe

看到 megacave / 更新相关日志后 Ctrl+C:
  python tmp/show_http_capture.py

抓取内容：
  - request：PreparedRequest 最终 method/url/headers/body
  - plaintext：Fernet.encrypt 前业务明文
  - response：含响应 headers；show_http_capture 可解密 body
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

try:
    import frida
except ImportError:
    print("[-] pip install frida frida-tools")
    sys.exit(1)

try:
    import psutil
except ImportError:
    psutil = None
    print("[!] psutil 未安装 — 将依赖 Frida child_gating；建议: pip install psutil")

ROOT = Path(__file__).resolve().parents[1]
TMP = Path(__file__).resolve().parent
HOOK_JS = TMP / "hook_v22_http_capture.js"
PATCH_PY = TMP / "py_requests_patch.py"
OUT = TMP / "captured" / "http_capture"
DEFAULT_EXE = ROOT / "S2TD_Converter_v.2.2_CN_MT.exe"
TARGET_NAME_KEYS = ("s2td", "converter")


def has_window(pid: int) -> bool:
    import ctypes

    user32 = ctypes.windll.user32
    found = ctypes.c_bool(False)

    @ctypes.WINFUNCTYPE(ctypes.wintypes.BOOL, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM)
    def cb(hwnd, _):
        out = ctypes.wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(out))
        if out.value == pid and user32.IsWindowVisible(hwnd):
            found.value = True
            return False
        return True

    user32.EnumWindows(cb, 0)
    return bool(found.value)


def name_matches(name: str) -> bool:
    n = (name or "").lower()
    return any(k in n for k in TARGET_NAME_KEYS)


class V22Capture:
    def __init__(self):
        self.device = frida.get_local_device()
        self.sessions = {}
        self.scripts = {}
        self.hooked = set()
        self.running = True
        self.saw_megacave = False
        self._lock = threading.Lock()
        OUT.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_path = OUT / f"requests_v22_{stamp}.jsonl"
        self.events_path = OUT / f"events_v22_{stamp}.jsonl"
        # 预先创建空文件，避免「没有生成请求文件」的误解
        self.log_path.write_text("", encoding="utf-8")
        self.events_path.write_text("", encoding="utf-8")
        print(f"[+] target: PyInstaller v2.2 (auto version-check on startup)")
        print(f"[+] requests log -> {self.log_path}")
        print(f"[+] events       -> {self.events_path}")
        self.device.on("child-added", self._on_child_added)
        self.device.on("child-removed", self._on_child_removed)
        self.device.on("process-crashed", self._on_crashed)

    def hook_source(self) -> str:
        pre = (
            f"var PATCH_PATH = {json.dumps(str(PATCH_PY.resolve()))};\n"
            f"var CAPTURE_LOG = {json.dumps(str(self.log_path.resolve()))};\n"
        )
        return pre + HOOK_JS.read_text(encoding="utf-8")

    def on_message(self, message, data):
        if message["type"] == "error":
            print("[Frida Error]", message.get("stack") or message)
            return
        if message["type"] != "send":
            return
        p = message.get("payload")
        if not isinstance(p, dict):
            return
        with self.events_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(p, ensure_ascii=False) + "\n")
        tag = p.get("tag")
        summary = p.get("summary") or ""
        print(f"[CAP][{tag}] {summary}")
        if tag == "ssl_http":
            path = OUT / f"ssl_v22_{p.get('id', 0):04d}_{p.get('fn')}.txt"
            text = p.get("text") or ""
            path.write_text(text, encoding="utf-8", errors="replace")
            print(f"    -> {path}")
            if "lic.megacave" in text or "megacave" in text.lower():
                self.saw_megacave = True
                print("    [!] megacave / 更新相关流量已捕获（可 Ctrl+C 结束）")
        if tag == "status" and "patch OK" in summary:
            print("[!] requests/Fernet 已补丁；加密前明文会写入日志并在下方显示")
            print(f"    日志: {self.log_path}")

    def _on_child_added(self, child):
        try:
            print(f"[!] Frida child-added pid={child.pid} path={getattr(child, 'path', '')} "
                  f"identifier={getattr(child, 'identifier', '')}")
            # child 被 gating 挂起；先 attach 再 resume
            self.attach(child.pid, label="(child-gate)")
            try:
                self.device.resume(child.pid)
                print(f"[+] resumed child pid={child.pid}")
            except Exception as e:
                print(f"[!] resume child {child.pid}: {e}")
        except Exception as e:
            print(f"[-] child-added handler: {e}")
            try:
                self.device.resume(child.pid)
            except Exception:
                pass

    def _on_child_removed(self, child):
        print(f"[*] child-removed pid={getattr(child, 'pid', child)}")

    def _on_crashed(self, crash):
        print(f"[!] process-crashed: {crash}")

    def _tail_log(self):
        """Live-print plaintext / megacave lines from requests jsonl."""
        pos = 0
        while self.running:
            try:
                if not self.log_path.exists():
                    time.sleep(0.3)
                    continue
                with self.log_path.open("r", encoding="utf-8", errors="replace") as f:
                    f.seek(pos)
                    for ln in f:
                        pos = f.tell()
                        ln = ln.strip()
                        if not ln:
                            continue
                        try:
                            o = json.loads(ln)
                        except Exception:
                            continue
                        ch = o.get("channel")
                        if ch == "plaintext":
                            phase = o.get("phase")
                            print("\n**** PLAINTEXT ****", flush=True)
                            print(f"  phase={phase}", flush=True)
                            if o.get("fernet_key"):
                                print(f"  fernet_key={o['fernet_key']}", flush=True)
                            if o.get("material"):
                                print(f"  rsa_material={o['material']}", flush=True)
                            if o.get("json") is not None:
                                print(json.dumps(o["json"], ensure_ascii=False, indent=2), flush=True)
                            elif o.get("plaintext") is not None:
                                print(o["plaintext"], flush=True)
                            print("*******************\n", flush=True)
                        elif ch == "status":
                            print(f"[log][status] {o.get('msg')}", flush=True)
                        elif ch == "requests" and o.get("phase") == "request":
                            url = str(o.get("url") or "")
                            if "megacave" not in url.lower():
                                continue
                            self.saw_megacave = True
                            print(f"\n[HTTP] {o.get('method')} {url}", flush=True)
                            hdrs = o.get("headers") or {}
                            if hdrs:
                                keys_show = [
                                    "User-Agent",
                                    "Content-Type",
                                    "Accept",
                                    "Cf-Client-Cert-Der-Base64",
                                    "X-CSRF-TOKEN",
                                    "Authorization",
                                    "Cookie",
                                    "Content-Length",
                                ]
                                for k in keys_show:
                                    val = None
                                    for hk, hv in hdrs.items():
                                        if str(hk).lower() == k.lower():
                                            val = hv
                                            break
                                    if val is None:
                                        continue
                                    vs = str(val)
                                    if k.lower() == "cf-client-cert-der-base64":
                                        vs = vs[:64] + f"...({len(str(val))} chars)"
                                    elif k.lower() == "cookie" and len(vs) > 200:
                                        vs = vs[:200] + "..."
                                    print(f"  {k}: {vs}", flush=True)
                                print(f"  headers_total={len(hdrs)} (full in jsonl)", flush=True)
                        elif ch == "error":
                            print(f"[log][error] {o}", flush=True)
            except Exception:
                pass
            time.sleep(0.25)

    def attach(self, pid: int, label: str = "") -> bool:
        with self._lock:
            if pid in self.hooked:
                return False
            self.hooked.add(pid)
        try:
            name = ""
            if psutil:
                try:
                    name = psutil.Process(pid).name()
                except Exception:
                    pass
            print(f"[+] attach pid={pid} {name} {label}")
            session = self.device.attach(pid)
            try:
                session.enable_child_gating()
                print(f"[+] child_gating ON pid={pid}")
            except Exception as e:
                print(f"[!] child_gating failed pid={pid}: {e}")
            script = session.create_script(self.hook_source())
            script.on("message", self.on_message)
            script.load()
            self.sessions[pid] = session
            self.scripts[pid] = script
            threading.Thread(target=self._arm_loop, args=(pid,), daemon=True).start()
            if psutil:
                threading.Thread(target=self._watch_children, args=(pid,), daemon=True).start()
            if not getattr(self, "_tail_started", False):
                self._tail_started = True
                threading.Thread(target=self._tail_log, daemon=True).start()
            if not getattr(self, "_scan_started", False):
                self._scan_started = True
                threading.Thread(target=self._scan_by_name, daemon=True).start()
            return True
        except Exception as e:
            with self._lock:
                self.hooked.discard(pid)
            print(f"[-] attach failed pid={pid}: {e}")
            return False

    def _arm_loop(self, pid: int):
        script = self.scripts.get(pid)
        if not script:
            return
        for i in range(180):
            if not self.running:
                return
            time.sleep(0.5)
            try:
                st = script.exports_sync.status()
                if i in (2, 10, 30, 60) or st.get("patched"):
                    print(
                        f"[*] pid={pid} ssl_hooks={st.get('ssl')} "
                        f"patched={st.get('patched')} (arm #{i})"
                    )
                if st.get("patched"):
                    print(f"[+] confirmed requests patch on pid={pid}")
                    return
                script.exports_sync.scan_ssl()
                script.exports_sync.patch()
            except Exception as e:
                if i in (2, 10, 30):
                    print(f"[!] arm pid={pid}: {e}")
        print(f"[*] pid={pid} arm loop done (SSL may still capture without requests patch)")

    def _watch_children(self, parent: int):
        """psutil 兜底：枚举子进程并附加。"""
        known = {parent}
        while self.running and psutil:
            try:
                if not psutil.pid_exists(parent):
                    break
                for c in psutil.Process(parent).children(recursive=True):
                    if c.pid in known:
                        continue
                    known.add(c.pid)
                    try:
                        n = c.name()
                    except Exception:
                        n = ""
                    print(f"[!] psutil child {c.pid} {n}")
                    # PyInstaller 子进程通常同名；其它子进程也试一下
                    if name_matches(n) or True:
                        self.attach(c.pid, label="(psutil-child)")
            except Exception:
                pass
            time.sleep(0.3)

    def _scan_by_name(self):
        """全局按进程名扫 S2TD（防止父子关系丢失）。"""
        if not psutil:
            return
        while self.running:
            try:
                for p in psutil.process_iter(["pid", "name"]):
                    try:
                        name = p.info.get("name") or ""
                        pid = p.info["pid"]
                        if pid in self.hooked:
                            continue
                        if not name_matches(name):
                            continue
                        # 优先有窗口的（真 GUI 子进程）
                        label = "(name-scan)"
                        if has_window(pid):
                            label = "(name-scan/window)"
                        print(f"[!] name-scan hit pid={pid} {name}")
                        self.attach(pid, label=label)
                    except Exception:
                        continue
            except Exception:
                pass
            time.sleep(1.0)

    def spawn(self, exe: Path):
        print(f"[+] frida.spawn (suspended) {exe}")
        pid = self.device.spawn([str(exe)], cwd=str(exe.parent))
        self.attach(pid, label="(spawn/suspended)")
        time.sleep(0.2)
        self.device.resume(pid)
        print(f"[+] resumed pid={pid}")
        print("[!] 等待 child（PyInstaller 真进程）+ Fernet/requests 补丁…")
        print("[!] 捕获后 Ctrl+C → python tmp/show_http_capture.py")

    def wait_attach(self, name: str) -> bool:
        name_l = name.lower()
        print(f"[*] 附加已运行进程: {name}")
        print("[!] 注意: 若更新请求已在启动时发完，可能抓不到；建议改用默认 spawn")
        for _ in range(300):
            if not psutil:
                break
            for p in psutil.process_iter(["pid", "name"]):
                try:
                    if (p.info["name"] or "").lower() != name_l:
                        continue
                    if has_window(p.info["pid"]):
                        return self.attach(p.info["pid"], label="(wait)")
                except Exception:
                    continue
            time.sleep(0.5)
        if psutil:
            for p in psutil.process_iter(["pid", "name"]):
                try:
                    if (p.info["name"] or "").lower() == name_l:
                        return self.attach(p.info["pid"], label="(name)")
                except Exception:
                    continue
        return False

    def loop(self):
        try:
            ticks = 0
            while self.running:
                time.sleep(1)
                ticks += 1
                if ticks in (5, 15, 30) and not self.saw_megacave:
                    print(
                        f"[*] still waiting… hooked={sorted(self.hooked)} "
                        f"log_size={self.log_path.stat().st_size if self.log_path.exists() else 0}"
                    )
                if not self.saw_megacave and self.log_path.exists():
                    try:
                        if "megacave" in self.log_path.read_text(encoding="utf-8", errors="ignore").lower():
                            self.saw_megacave = True
                            print("[!] requests 日志中已出现 megacave（可 Ctrl+C）")
                    except Exception:
                        pass
        except KeyboardInterrupt:
            print("\n[!] stopping...")
        self.running = False
        for s in list(self.scripts.values()):
            try:
                s.unload()
            except Exception:
                pass
        for s in list(self.sessions.values()):
            try:
                s.detach()
            except Exception:
                pass
        print(f"[+] hooked={sorted(self.hooked)}")
        print(f"[+] saw_megacave={self.saw_megacave}")
        print(f"[+] requests log: {self.log_path}")
        if self.log_path.exists():
            print(f"[+] size={self.log_path.stat().st_size}")
            if self.log_path.stat().st_size == 0:
                print("[!] 日志为空：未挂到 Python 子进程或补丁未生效。")
                print("    请确认已关掉其它 S2TD 实例，并 pip install psutil frida")
        print("[+] next: python tmp/show_http_capture.py")


def main() -> int:
    ap = argparse.ArgumentParser(description="v2.2 CN_MT HTTP capture (auto update on start)")
    g = ap.add_mutually_exclusive_group(required=False)
    g.add_argument("-e", "--exe", help="spawn EXE (recommended)")
    g.add_argument("-w", "--wait", metavar="NAME", help="attach after GUI (may miss update)")
    g.add_argument("-p", "--pid", type=int)
    args = ap.parse_args()

    if not HOOK_JS.exists() or not PATCH_PY.exists():
        print("[-] missing hook/patch files")
        return 1

    # 先清掉残留进程，避免 child 归属混乱 / 已错过更新请求
    if psutil and not args.pid and not args.wait:
        killed = []
        for p in psutil.process_iter(["pid", "name"]):
            try:
                if name_matches(p.info.get("name") or ""):
                    print(f"[!] kill leftover pid={p.info['pid']} {p.info['name']}")
                    p.kill()
                    killed.append(p.info["pid"])
            except Exception:
                pass
        if killed:
            time.sleep(1.0)

    cap = V22Capture()
    if args.pid:
        ok = cap.attach(args.pid)
    elif args.wait:
        ok = cap.wait_attach(args.wait)
    else:
        exe = Path(args.exe) if args.exe else DEFAULT_EXE
        if not exe.is_file():
            exe = ROOT / str(exe)
        if not exe.is_file():
            print(f"[-] exe not found: {exe}")
            return 1
        cap.spawn(exe)
        ok = True
    if not ok:
        return 1
    cap.loop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
