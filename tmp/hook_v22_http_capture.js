/**
 * v2.2 HTTP capture — SSL-first (reliable), optional Python patch after Py_Initialize.
 */
'use strict';

var captureId = 0;
var pyPatched = false;
var sslHooked = {};
var initHooked = false;

function emit(tag, payload) {
    payload = payload || {};
    payload.tag = tag;
    payload.id = ++captureId;
    payload.ts = Date.now();
    send(payload);
}

function findMod(name) {
    try { return Process.getModuleByName(name); } catch (e) { return null; }
}

function resolveExp(mod, name) {
    if (!mod) return null;
    try { return mod.getExportByName(name); } catch (e) { return null; }
}

function hookSslMod(mod) {
    if (!mod) return 0;
    var key = mod.name + '@' + mod.base;
    if (sslHooked[key]) return 0;
    var n = 0;
    ['SSL_write', 'SSL_read'].forEach(function (fn) {
        var addr = resolveExp(mod, fn);
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.buf = args[1];
                this.len = args[2].toInt32();
            },
            onLeave: function (retval) {
                var got = retval.toInt32();
                if (got <= 0 || got > 2 * 1024 * 1024 || !this.buf) return;
                try {
                    var u8 = new Uint8Array(this.buf.readByteArray(got));
                    var s = '';
                    var lim = Math.min(u8.length, 131072);
                    for (var i = 0; i < lim; i++) {
                        var c = u8[i];
                        s += (c >= 32 && c < 127) || c === 10 || c === 13 ? String.fromCharCode(c) : '.';
                    }
                    var hit =
                        s.indexOf('HTTP/') >= 0 ||
                        s.indexOf('GET ') >= 0 ||
                        s.indexOf('POST ') >= 0 ||
                        s.indexOf('Host:') >= 0 ||
                        s.indexOf('megacave') >= 0 ||
                        s.indexOf('{"data"') >= 0 ||
                        s.indexOf('"data"') >= 0;
                    if (hit) {
                        emit('ssl_http', {
                            summary: fn + ' ' + got + 'B from ' + mod.name,
                            fn: fn,
                            module: mod.name,
                            text: s
                        });
                    }
                } catch (e) {}
            }
        });
        n++;
        emit('status', { summary: 'SSL hooked ' + fn + ' @ ' + mod.name });
    });
    if (n) sslHooked[key] = 1;
    return n;
}

function scanSsl() {
    var total = 0;
    Process.enumerateModules().forEach(function (m) {
        var low = m.name.toLowerCase();
        if (low.indexOf('libssl') >= 0 || low === 'ssl.dll') {
            total += hookSslMod(m);
        }
    });
    return total;
}

function tryPatchPython() {
    if (pyPatched) return true;
    if (typeof PATCH_PATH === 'undefined') return false;

    var mod = findMod('python310.dll') || findMod('python3.dll');
    if (!mod) return false;

    var isInit = resolveExp(mod, 'Py_IsInitialized');
    var ensure = resolveExp(mod, 'PyGILState_Ensure');
    var release = resolveExp(mod, 'PyGILState_Release');
    var run = resolveExp(mod, 'PyRun_SimpleString');
    var errPrint = resolveExp(mod, 'PyErr_PrintEx');
    var errClear = resolveExp(mod, 'PyErr_Clear');

    if (!ensure || !release || !run) {
        emit('status', { summary: 'python exports incomplete' });
        return false;
    }

    if (isInit) {
        var Py_IsInitialized = new NativeFunction(isInit, 'int', []);
        if (Py_IsInitialized() === 0) {
            // wait for init
            hookPyInitialize(mod);
            return false;
        }
    }

    var PyGILState_Ensure = new NativeFunction(ensure, 'int', []);
    var PyGILState_Release = new NativeFunction(release, 'void', ['int']);
    var PyRun_SimpleString = new NativeFunction(run, 'int', ['pointer']);

    var path = ('' + PATCH_PATH).replace(/\\/g, '/');
    var log = (typeof CAPTURE_LOG !== 'undefined' ? ('' + CAPTURE_LOG) : '').replace(/\\/g, '/');

    // Prefer full file patch. Fallback: inline Fernet + Session.send(headers).
    var code =
        'import os\n' +
        'os.environ["S2TD_HTTP_CAPTURE_LOG"]=r"' + log + '"\n' +
        'try:\n' +
        ' p=r"' + path + '"\n' +
        ' g={"__name__":"__s2td_patch__","__file__":p}\n' +
        ' exec(compile(open(p,"r",encoding="utf-8").read(),p,"exec"),g,g)\n' +
        'except Exception as _e:\n' +
        ' import json,time,threading\n' +
        ' LOG=r"' + log + '"\n' +
        ' os.makedirs(os.path.dirname(LOG),exist_ok=True)\n' +
        ' def _log(o):\n' +
        '  try:\n' +
        '   o.setdefault("ts",time.time())\n' +
        '   open(LOG,"a",encoding="utf-8").write(json.dumps(o,ensure_ascii=False,default=str)+"\\n")\n' +
        '  except: pass\n' +
        ' _log({"channel":"error","msg":"file patch failed","err":str(_e)})\n' +
        ' def _hdrs(h):\n' +
        '  out={}\n' +
        '  try:\n' +
        '   for k,v in (h.items() if hasattr(h,"items") else dict(h or {}).items()):\n' +
        '    out[str(k)]=v if isinstance(v,str) else str(v)\n' +
        '  except: pass\n' +
        '  return out\n' +
        ' def _install():\n' +
        '  from cryptography.fernet import Fernet\n' +
        '  from requests.sessions import Session\n' +
        '  if not getattr(Fernet.encrypt,"_s2td",False):\n' +
        '   _re=Fernet.encrypt\n' +
        '   def _enc(self,data):\n' +
        '    try:\n' +
        '     pt=data.decode("utf-8","replace") if isinstance(data,bytes) else str(data)\n' +
        '     _log({"channel":"plaintext","phase":"fernet.encrypt","plaintext":pt})\n' +
        '     print("[S2TD-PLAINTEXT]",pt[:4000],flush=True)\n' +
        '    except: pass\n' +
        '    return _re(self,data)\n' +
        '   _enc._s2td=True; Fernet.encrypt=_enc\n' +
        '  if not getattr(Session.send,"_s2td",False):\n' +
        '   _rs=Session.send\n' +
        '   def _send(self,req,**kw):\n' +
        '    try:\n' +
        '     b=req.body\n' +
        '     if isinstance(b,bytes):\n' +
        '      try: b=b.decode("utf-8")\n' +
        '      except: b=b.hex()\n' +
        '     _log({"channel":"requests","phase":"request","method":req.method,"url":req.url,"headers":_hdrs(req.headers),"body":b})\n' +
        '    except: pass\n' +
        '    r=_rs(self,req,**kw)\n' +
        '    try:\n' +
        '     _log({"channel":"requests","phase":"response","url":req.url,"status":r.status_code,"headers":_hdrs(r.headers),"body":r.text[:200000]})\n' +
        '    except: pass\n' +
        '    return r\n' +
        '   _send._s2td=True; Session.send=_send\n' +
        '  _log({"channel":"status","msg":"fallback inline fernet+send+headers"})\n' +
        '  return True\n' +
        ' def _boot():\n' +
        '  for i in range(150):\n' +
        '   try:\n' +
        '    if _install(): return\n' +
        '   except Exception as e: _log({"channel":"error","err":str(e)})\n' +
        '   time.sleep(0.4)\n' +
        ' threading.Thread(target=_boot,daemon=True).start()\n';
    var st = PyGILState_Ensure();
    var rc = -1;
    try {
        if (errClear) new NativeFunction(errClear, 'void', [])();
        rc = PyRun_SimpleString(Memory.allocUtf8String(code));
        if (rc !== 0 && errPrint) {
            new NativeFunction(errPrint, 'void', ['int'])(0);
        }
    } catch (e) {
        emit('error', { summary: 'PyRun throw ' + e });
    }
    PyGILState_Release(st);

    if (rc === 0) {
        pyPatched = true;
        emit('status', { summary: 'patch OK (file/inline Fernet+requests) log=' + log });
        return true;
    }
    emit('status', { summary: 'PyRun_SimpleString rc=' + rc + ' (SSL capture still active)' });
    return false;
}

function hookPyInitialize(mod) {
    if (initHooked) return;
    var names = ['Py_Initialize', 'Py_InitializeEx', 'Py_InitializeFromConfig'];
    for (var i = 0; i < names.length; i++) {
        var addr = resolveExp(mod, names[i]);
        if (!addr) continue;
        initHooked = true;
        Interceptor.attach(addr, {
            onLeave: function () {
                emit('status', { summary: 'Python initialized — retry patch' });
                setTimeout(tryPatchPython, 300);
                setTimeout(tryPatchPython, 1000);
                setTimeout(tryPatchPython, 3000);
            }
        });
        emit('status', { summary: 'watching ' + names[i] });
        return;
    }
}

function setupLoaderWatch() {
    var k32 = findMod('kernel32.dll');
    if (!k32) return;
    ['LoadLibraryW', 'LoadLibraryExW', 'LoadLibraryA', 'LoadLibraryExA'].forEach(function (name) {
        var a = resolveExp(k32, name);
        if (!a) return;
        Interceptor.attach(a, {
            onEnter: function (args) {
                try {
                    this.p = name.indexOf('W') >= 0 ? args[0].readUtf16String() : args[0].readAnsiString();
                } catch (e) { this.p = ''; }
            },
            onLeave: function () {
                if (!this.p) return;
                var low = this.p.toLowerCase();
                if (low.indexOf('libssl') >= 0 || low.indexOf('ssl') >= 0) {
                    scanSsl();
                }
                if (low.indexOf('python3') >= 0) {
                    var mod = findMod('python310.dll') || findMod('python3.dll');
                    if (mod) hookPyInitialize(mod);
                    setTimeout(tryPatchPython, 500);
                    scanSsl();
                }
            }
        });
    });
}

emit('status', { summary: 'hook_v22_http_capture.js loaded (SSL-first)' });
setupLoaderWatch();
var n = scanSsl();
emit('status', { summary: 'initial SSL hooks=' + n });

var py = findMod('python310.dll') || findMod('python3.dll');
if (py) {
    hookPyInitialize(py);
    tryPatchPython();
}

var ticks = 0;
setInterval(function () {
    ticks++;
    scanSsl();
    if (!pyPatched && ticks % 4 === 0) tryPatchPython();
    if (ticks === 8 || ticks === 20) {
        emit('status', {
            summary: 'heartbeat sslMods=' + Object.keys(sslHooked).length +
                ' patched=' + pyPatched +
                ' modules=' + Process.enumerateModules().length
        });
    }
}, 500);

rpc.exports = {
    patch: function () { return tryPatchPython(); },
    status: function () {
        return { patched: pyPatched, ssl: Object.keys(sslHooked).length };
    },
    scanSsl: function () { return scanSsl(); }
};
