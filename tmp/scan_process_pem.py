#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
不注入 Frida：用 ReadProcessMemory 扫描目标进程里的 PEM / RSA 材料。

用法（先手动启动并点出 GUI）:
  python tmp/scan_process_pem.py -n S2TD_Converter_v.2.5_EN.exe
  python tmp/scan_process_pem.py -p <子进程PID>
"""

from __future__ import annotations

import argparse
import ctypes
import re
import sys
from ctypes import wintypes
from datetime import datetime
from pathlib import Path

try:
    import psutil
except ImportError:
    print("[-] pip install psutil")
    sys.exit(1)

TMP = Path(__file__).resolve().parent
OUT = TMP / "captured" / "pem_ext"
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


PEM_RE = re.compile(
    br"-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \1-----",
    re.DOTALL,
)

MARKERS = [
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PUBLIC KEY-----",
    b"-----BEGIN PUBLIC KEY-----",
    b"-----BEGIN CERTIFICATE-----",
    b"gAAAAA",  # Fernet token prefix (ascii)
]


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def process_has_visible_window(pid: int) -> bool:
    user32 = ctypes.windll.user32
    found = ctypes.c_bool(False)

    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    def enum_proc(hwnd, _lparam):
        pid_out = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid_out))
        if pid_out.value == pid and user32.IsWindowVisible(hwnd):
            found.value = True
            return False
        return True

    user32.EnumWindows(enum_proc, 0)
    return bool(found.value)


def find_targets(name: str):
    name_l = name.lower()
    stem = name_l[:-4] if name_l.endswith(".exe") else name_l
    hits = []
    for p in psutil.process_iter(["pid", "name", "memory_info"]):
        try:
            n = (p.info["name"] or "").lower()
            if n != name_l and n != stem and n != stem + ".exe":
                continue
            rss = p.info["memory_info"].rss if p.info.get("memory_info") else 0
            win = process_has_visible_window(p.info["pid"])
            hits.append((p.info["pid"], rss, win, p.info["name"]))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    # prefer window + higher rss (real child)
    hits.sort(key=lambda x: (not x[2], -x[1]))
    return hits


def readable(protect: int) -> bool:
    if protect & PAGE_GUARD:
        return False
    # PAGE_READONLY 2, READWRITE 4, WRITECOPY 8, EXECUTE_READ 0x20, EXECUTE_READWRITE 0x40, EXECUTE_WRITECOPY 0x80
    return bool(protect & (0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80))


def scan_pid(pid: int) -> list[tuple[str, bytes]]:
    access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    h = kernel32.OpenProcess(access, False, pid)
    if not h:
        raise OSError(f"OpenProcess({pid}) failed err={ctypes.get_last_error()}")

    found = []
    seen = set()
    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0
    read_buf = ctypes.create_string_buffer(1024 * 1024)

    try:
        while addr < 0x7FFFFFFFFFFF:
            got = kernel32.VirtualQueryEx(
                h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)
            )
            if not got:
                break
            base = mbi.BaseAddress or 0
            size = int(mbi.RegionSize or 0)
            if size == 0:
                break
            next_addr = base + size
            if mbi.State == MEM_COMMIT and readable(mbi.Protect) and size <= 64 * 1024 * 1024:
                offset = 0
                while offset < size:
                    chunk = min(len(read_buf), size - offset)
                    nread = ctypes.c_size_t(0)
                    ok = kernel32.ReadProcessMemory(
                        h,
                        ctypes.c_void_p(base + offset),
                        read_buf,
                        chunk,
                        ctypes.byref(nread),
                    )
                    if ok and nread.value:
                        data = read_buf.raw[: nread.value]
                        for m in PEM_RE.finditer(data):
                            pem = m.group(0)
                            # basic sanity
                            if b"%" in pem[:80]:
                                continue
                            if len(pem) < 100 or len(pem) > 20000:
                                continue
                            key = hash(pem)
                            if key in seen:
                                continue
                            seen.add(key)
                            kind = m.group(1).decode("ascii", "replace")
                            found.append((kind, pem))
                        # also note fernet-looking ascii (not saved as pem)
                        if b"gAAAAA" in data and "FERNET_HINT" not in seen:
                            idx = data.find(b"gAAAAA")
                            frag = data[idx : idx + 120]
                            if all(32 <= c < 127 for c in frag[:20]):
                                seen.add("FERNET_HINT")
                                found.append(("FERNET_HINT", frag))
                    offset += chunk
            addr = next_addr
            if addr <= base:
                break
    finally:
        kernel32.CloseHandle(h)
    return found


def main() -> int:
    ap = argparse.ArgumentParser(description="External PEM scan without Frida")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-p", "--pid", type=int)
    g.add_argument("-n", "--name", type=str)
    args = ap.parse_args()

    print(f"[+] admin={is_admin()}")
    OUT.mkdir(parents=True, exist_ok=True)

    pids = []
    if args.pid:
        pids = [args.pid]
    else:
        hits = find_targets(args.name)
        if not hits:
            print(f"[-] process not found: {args.name}")
            print("    请先手动启动程序，等 GUI 出现后再运行")
            return 1
        for pid, rss, win, name in hits:
            print(f"[*] candidate pid={pid} name={name} rss={rss} window={win}")
        # scan window-bearing first; if none, scan largest rss
        win_pids = [h[0] for h in hits if h[2]]
        pids = win_pids or [hits[0][0]]

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    total = 0
    for pid in pids:
        print(f"[+] scanning pid={pid} ...")
        try:
            items = scan_pid(pid)
        except Exception as e:
            print(f"[-] scan pid={pid} failed: {e}")
            continue
        print(f"[+] hits={len(items)}")
        for i, (kind, blob) in enumerate(items, 1):
            total += 1
            if kind == "FERNET_HINT":
                path = OUT / f"{stamp}_{pid}_{i:02d}_fernet_hint.txt"
                path.write_bytes(blob)
            else:
                path = OUT / f"{stamp}_{pid}_{i:02d}_{kind.replace(' ', '_')}.pem"
                path.write_bytes(blob)
            print(f"    -> {path} ({kind}, {len(blob)} bytes)")

    print(f"[+] done, saved={total} under {OUT}")
    return 0 if total else 1


if __name__ == "__main__":
    raise SystemExit(main())
