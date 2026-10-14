/*


要将 CER 证书和私钥（KEY）转换为 P12（PKCS#12）格式，然后导入到系统。

openssl pkcs12 -export -in certificate.cer -inkey private.key -out output.p12 -name "My Certificate"

*/

console.log("[+] libssl-1_1.dll 实时检测Hook启动");

var hookInstalled = false;

// 立即检查DLL是否已经加载
function checkExistingDLL() {
    try {
        var libssl = Process.findModuleByName("libssl-1_1.dll");
        if (!libssl) {
            libssl = Process.findModuleByName("libssl-1_1-x64.dll");
        }

        if (libssl) {
            console.log("[+] 检测到已加载的目标DLL: " + libssl.name + " at " + libssl.base);
            console.log("[+] 模块路径: " + libssl.path);
            console.log("[+] 模块大小: " + libssl.size + " 字节");
            installSSLHooks(libssl);
            return true;
        }
        return false;
    } catch (e) {
        console.log("[-] 检查现有DLL时出错: " + e.message);
        return false;
    }
}

// 监听模块加载事件
function setupModuleLoadListener() {
    try {
        // 使用Process.setExceptionHandler监听所有异常和模块加载
        var originalLoadLibrary = Module.findExportByName("kernel32.dll", "LoadLibraryA");
        var originalLoadLibraryW = Module.findExportByName("kernel32.dll", "LoadLibraryW");
        var originalLoadLibraryEx = Module.findExportByName("kernel32.dll", "LoadLibraryExA");
        var originalLoadLibraryExW = Module.findExportByName("kernel32.dll", "LoadLibraryExW");
        
        // Hook LoadLibraryA
        if (originalLoadLibrary) {
            Interceptor.attach(originalLoadLibrary, {
                onEnter: function(args) {
                    this.libraryName = args[0].readAnsiString();
                },
                onLeave: function(retval) {
                    if (this.libraryName && /libssl-1_1.*\.dll/i.test(this.libraryName)) {
                        console.log("[!] 检测到目标DLL正在加载: " + this.libraryName);
                        setTimeout(function() {
                            checkAndHookDLL();
                        }, 10);
                    }
                }
            });
        }
        
        // Hook LoadLibraryW
        if (originalLoadLibraryW) {
            Interceptor.attach(originalLoadLibraryW, {
                onEnter: function(args) {
                    this.libraryName = args[0].readUtf16String();
                },
                onLeave: function(retval) {
                    if (this.libraryName && this.libraryName.toLowerCase().indexOf("libssl-1_1.dll") !== -1) {
                        console.log("[!] 检测到 libssl-1_1.dll 正在加载 (Unicode): " + this.libraryName);
                        setTimeout(function() {
                            checkAndHookDLL();
                        }, 10);
                    }
                }
            });
        }
        
        // Hook LoadLibraryExA
        if (originalLoadLibraryEx) {
            Interceptor.attach(originalLoadLibraryEx, {
                onEnter: function(args) {
                    this.libraryName = args[0].readAnsiString();
                },
                onLeave: function(retval) {
                    if (this.libraryName && this.libraryName.toLowerCase().indexOf("libssl-1_1.dll") !== -1) {
                        console.log("[!] 检测到 libssl-1_1.dll 正在加载 (Ex): " + this.libraryName);
                        setTimeout(function() {
                            checkAndHookDLL();
                        }, 10);
                    }
                }
            });
        }
        
        // Hook LoadLibraryExW
        if (originalLoadLibraryExW) {
            Interceptor.attach(originalLoadLibraryExW, {
                onEnter: function(args) {
                    this.libraryName = args[0].readUtf16String();
                },
                onLeave: function(retval) {
                    if (this.libraryName && this.libraryName.toLowerCase().indexOf("libssl-1_1.dll") !== -1) {
                        console.log("[!] 检测到 libssl-1_1.dll 正在加载 (ExW): " + this.libraryName);
                        setTimeout(function() {
                            checkAndHookDLL();
                        }, 10);
                    }
                }
            });
        }
        
        console.log("[+] 模块加载监听器已设置");
        
    } catch (e) {
        console.log("[-] 设置模块加载监听器失败: " + e.message);
    }
}

// 检查并Hook DLL
function checkAndHookDLL() {
    try {
        var libssl = Process.findModuleByName("libssl-1_1.dll");
        if (!libssl) {
            libssl = Process.findModuleByName("libssl-1_1-x64.dll");
        }

        if (libssl) {
            installSSLHooks(libssl);
        }
    } catch (e) {
        // This can happen if the module is not loaded yet, which is fine.
    }
}

// 从X509*对象提取证书数据
function extractCertificateFromX509(x509Ptr) {
    try {
        console.log("[+] 处理X509*对象，指针: " + x509Ptr);
        
        if (!x509Ptr || x509Ptr.isNull()) {
            console.log("[-] X509指针为空");
            return null;
        }
        
        var certData = null;
        
        // 方法2: 使用OpenSSL的i2d_X509 API提取DER数据
        if (!certData) {
            try {
                console.log("[+] 尝试使用i2d_X509 API提取DER数据");
                
                // 查找i2d_X509函数
                var libcrypto = Process.findModuleByName("libcrypto-1_1.dll");
                if (libcrypto) {
                    var i2d_X509 = libcrypto.getExportByName("i2d_X509");
                    if (i2d_X509) {
                        console.log("[+] 找到i2d_X509函数: " + i2d_X509);
                        
                        // 分配内存用于存储DER数据指针
                        var derPtrPtr = Memory.alloc(Process.pointerSize);
                        derPtrPtr.writePointer(ptr(0));
                        
                        // 调用i2d_X509获取DER数据长度和内容
                        var derLength = new NativeFunction(i2d_X509, 'int', ['pointer', 'pointer'])(x509Ptr, derPtrPtr);
                        
                        if (derLength > 0) {
                            var derPtr = derPtrPtr.readPointer();
                            if (derPtr && !derPtr.isNull()) {
                                console.log("[+] i2d_X509成功，DER长度: " + derLength + " 字节");
                                certData = derPtr.readByteArray(derLength);
                                
                                // 释放OpenSSL分配的内存
                                // try {
                                //     var OPENSSL_cleanup = libcrypto.getExportByName("OPENSSL_cleanup");
                                //     if (OPENSSL_cleanup) {
                                //         new NativeFunction(OPENSSL_cleanup, 'void', ['pointer'])(derPtr);
                                //     }
                                // } catch (e) {
                                //     console.log("[-] 释放内存失败: " + e.message);
                                // }
                            }
                        } else {
                            console.log("[-] i2d_X509返回长度无效: " + derLength);
                        }
                    } else {
                        console.log("[-] 未找到i2d_X509函数");
                    }
                } else {
                    console.log("[-] 未找到libcrypto-1_1.dll模块");
                }
            } catch (e) {
                console.log("[-] i2d_X509调用失败: " + e.message);
            }
        }
                
        if (certData) {
            return certData;
        } else {
            console.log("[-] 所有方法都无法从X509对象提取证书数据");
            return null;
        }
        
    } catch (e) {
        console.log("[-] 处理X509对象失败: " + e.message);
        return null;
    }
}

// 从DER证书数据中提取序列号
function extractSerialNumberFromCert(derData) {
    try {
        if (!derData || derData.byteLength < 10) {
            return null;
        }

        var bytes = new Uint8Array(derData);
        
        // 简单的ASN.1 DER解析来查找序列号
        // 序列号通常在版本号之后，发行者之前
        for (var i = 0; i < bytes.length - 20; i++) {
            // 查找INTEGER标签 (0x02) 后跟长度
            if (bytes[i] === 0x02) {
                var length = bytes[i + 1];
                
                // 序列号长度通常在1-20字节之间
                if (length > 0 && length <= 20 && (i + 1 + length) < bytes.length) {
                    var serialBytes = bytes.slice(i + 2, i + 2 + length);
                    
                    // 跳过版本号(通常是很小的数字)，查找真正的序列号
                    if (length > 4 || serialBytes[0] > 0x03) {
                        var serialHex = "";
                        for (var j = 0; j < serialBytes.length; j++) {
                            var hex = serialBytes[j].toString(16).toUpperCase();
                            if (hex.length === 1) hex = "0" + hex;
                            serialHex += hex;
                        }
                        
                        // 验证这看起来像一个合理的序列号
                        if (serialHex.length >= 8 && serialHex !== "00000000") {
                            return serialHex;
                        }
                    }
                }
            }
        }
        
        return null;
        
    } catch (e) {
        console.log("[-] 提取序列号失败: " + e.message);
        return null;
    }
}

// 提取并保存证书
function extractAndSaveCertificate(certPtr, source) {
    try {
        console.log("[+] 开始提取完整证书，来源: " + source);
        
        if (!certPtr || certPtr.isNull()) {
            console.log("[-] 证书指针无效");
            return false;
        }
        
        var certData = extractCertificateFromX509(certPtr);
        if (certData) {
            console.log("[+] 成功从X509对象提取证书数据");

            var serialNumber = extractSerialNumberFromCert(certData);
            var filename;
            if (serialNumber) {
                filename = "cert_" + serialNumber + ".der";
                console.log("[+] 提取到证书序列号: " + serialNumber);
                // 直接保存二进制DER数据
                var file = new File(filename, "wb");
                file.write(certData);
                file.close();
                
                console.log("[+] DER证书已保存: " + filename);
                console.log("[+] 文件大小: " + certData.byteLength + " 字节");
            }
            return filename;
        }
        
        console.log("[-] 证书提取失败");
        
    } catch (e) {
        console.log("[-] 提取证书过程失败: " + e.message);
        console.log("[-] 错误堆栈: " + e.stack);
        return null;
    }
}

// 设置客户端证书Hook
function setupClientCertificateHooks(sslFunctions) {
    try {
        console.log("[+] 开始设置客户端证书Hook");
        
        // Hook SSL_CTX_use_certificate - 加载证书到SSL上下文
        if (sslFunctions.SSL_CTX_use_certificate) {
            Interceptor.attach(sslFunctions.SSL_CTX_use_certificate, {
                onEnter: function(args) {
                    this.ctx = args[0];
                    this.cert = args[1];
                    
                    try {
                        console.log("[+] SSL_CTX_use_certificate 被调用");
                        extractAndSaveCertificate(this.cert, "SSL_CTX_use_certificate");
                    } catch (e) {
                        console.log("[-] 提取证书信息失败: " + e.message);
                    }
                },
                onLeave: function(retval) {
                    console.log("[+] SSL_CTX_use_certificate 返回: " + retval);
                }
            });
            console.log("[+] SSL_CTX_use_certificate Hook成功");
        }
        
        // Hook SSL_use_certificate - 加载证书到SSL连接
        if (sslFunctions.SSL_use_certificate) {
            Interceptor.attach(sslFunctions.SSL_use_certificate, {
                onEnter: function(args) {
                    this.ssl = args[0];
                    this.cert = args[1];
                    console.log("[+] SSL_use_certificate 被调用");
                },
                onLeave: function(retval) {
                    console.log("[+] SSL_use_certificate 返回: " + retval);
                }
            });
            console.log("[+] SSL_use_certificate Hook成功");
        }
        
        // Hook SSL_CTX_use_certificate_file - 从文件加载证书
        if (sslFunctions.SSL_CTX_use_certificate_file) {
            Interceptor.attach(sslFunctions.SSL_CTX_use_certificate_file, {
                onEnter: function(args) {
                    this.ctx = args[0];
                    this.file = args[1].readAnsiString();
                    this.type = args[2].toInt32();
                    
                    console.log("[!] SSL_CTX_use_certificate_file 被调用");
                    console.log("[!] 证书文件路径: " + this.file);
                    console.log("[!] 证书类型: " + (this.type === 1 ? "PEM" : "DER"));
                },
                onLeave: function(retval) {
                    console.log("[+] SSL_CTX_use_certificate_file 返回: " + retval);
                }
            });
            console.log("[+] SSL_CTX_use_certificate_file Hook成功");
        }
        
        // Hook SSL_use_certificate_file
        if (sslFunctions.SSL_use_certificate_file) {
            Interceptor.attach(sslFunctions.SSL_use_certificate_file, {
                onEnter: function(args) {
                    this.ssl = args[0];
                    this.file = args[1].readAnsiString();
                    this.type = args[2].toInt32();
                    
                    console.log("[!] SSL_use_certificate_file 被调用");
                    console.log("[!] 证书文件路径: " + this.file);
                    console.log("[!] 证书类型: " + (this.type === 1 ? "PEM" : "DER"));
                    
                    // 仅记录日志，不保存证书文件
                },
                onLeave: function(retval) {
                    console.log("[+] SSL_use_certificate_file 返回: " + retval);
                }
            });
            console.log("[+] SSL_use_certificate_file Hook成功");
        }
        
        // Hook私钥加载函数
        if (sslFunctions.SSL_CTX_use_PrivateKey_file) {
            Interceptor.attach(sslFunctions.SSL_CTX_use_PrivateKey_file, {
                onEnter: function(args) {
                    this.ctx = args[0];
                    this.file = args[1].readAnsiString();
                    this.type = args[2].toInt32();
                    
                    console.log("[!] SSL_CTX_use_PrivateKey_file 被调用");
                    console.log("[!] 私钥文件路径: " + this.file);
                    console.log("[!] 私钥类型: " + (this.type === 1 ? "PEM" : "DER"));
                },
                onLeave: function(retval) {
                    console.log("[+] SSL_CTX_use_PrivateKey_file 返回: " + retval);
                }
            });
            console.log("[+] SSL_CTX_use_PrivateKey_file Hook成功");
        }
        
        if (sslFunctions.SSL_use_PrivateKey_file) {
            Interceptor.attach(sslFunctions.SSL_use_PrivateKey_file, {
                onEnter: function(args) {
                    this.ssl = args[0];
                    this.file = args[1].readAnsiString();
                    this.type = args[2].toInt32();
                    
                    console.log("[!] SSL_use_PrivateKey_file 被调用");
                    console.log("[!] 私钥文件路径: " + this.file);
                    console.log("[!] 私钥类型: " + (this.type === 1 ? "PEM" : "DER"));
                },
                onLeave: function(retval) {
                    console.log("[+] SSL_use_PrivateKey_file 返回: " + retval);
                }
            });
            console.log("[+] SSL_use_PrivateKey_file Hook成功");
        }
        
        console.log("[+] 客户端证书Hook设置完成");
        
    } catch (e) {
        console.log("[-] 设置客户端证书Hook失败: " + e.message);
    }
}

// 安装SSL Hook
function installSSLHooks(libssl) {
    if (hookInstalled) {
        console.log("[+] SSL Hook已安装，跳过重复安装");
        return;
    }
    
    try {
        console.log("[+] 开始安装SSL Hook到 " + libssl.base);
        
        var exports = libssl.enumerateExports();
        console.log("[+] 枚举到 " + exports.length + " 个导出函数");
        
        var sslFunctions = {
            SSL_write: null,
            SSL_read: null,
            SSL_CTX_set_verify: null,
            SSL_set_verify: null,
            SSL_CTX_set_verify_mode: null,
            SSL_set_verify_mode: null,
            SSL_CTX_use_certificate: null,
            SSL_use_certificate: null,
            SSL_CTX_use_certificate_file: null,
            SSL_use_certificate_file: null,
            SSL_CTX_use_PrivateKey: null,
            SSL_use_PrivateKey: null,
            SSL_CTX_use_PrivateKey_file: null,
            SSL_use_PrivateKey_file: null,
            SSL_CTX_load_cert_file: null,
            SSL_load_client_CA_file: null
        };
        
        // 查找SSL函数
        exports.forEach(function(exp) {
            if (sslFunctions.hasOwnProperty(exp.name)) {
                sslFunctions[exp.name] = exp.address;
                console.log("[+] 找到函数: " + exp.name + " @ " + exp.address);
            }
        });
        
        var foundCount = Object.values(sslFunctions).filter(function(addr) { return addr !== null; }).length;
        console.log("[+] 找到 " + foundCount + " 个SSL函数");
        
        // Hook客户端证书函数
        setupClientCertificateHooks(sslFunctions);
        
        // Hook证书验证函数
        if (sslFunctions.SSL_CTX_set_verify) {
            Interceptor.attach(sslFunctions.SSL_CTX_set_verify, {
                onEnter: function(args) {
                    console.log("[!] SSL_CTX_set_verify 被调用，禁用证书验证");
                    args[1] = ptr(0); // SSL_VERIFY_NONE
                }
            });
            console.log("[+] SSL_CTX_set_verify Hook成功");
        }
        
        if (sslFunctions.SSL_set_verify) {
            Interceptor.attach(sslFunctions.SSL_set_verify, {
                onEnter: function(args) {
                    console.log("[!] SSL_set_verify 被调用，禁用证书验证");
                    args[1] = ptr(0); // SSL_VERIFY_NONE
                }
            });
            console.log("[+] SSL_set_verify Hook成功");
        }
        
        // Hook数据传输函数
        if (sslFunctions.SSL_write) {
            Interceptor.attach(sslFunctions.SSL_write, {
                onEnter: function(args) {
                    this.ssl = args[0];
                    this.buffer = args[1];
                    this.length = args[2].toInt32();
                },
                onLeave: function(retval) {
                    if (this.length > 0 && this.length < 10000) {
                        try {
                            var data = this.buffer.readUtf8String(this.length);
                            if (data && (data.indexOf("POST") !== -1 || data.indexOf("GET") !== -1)) {
                                console.log("[!] SSL_write 捕获HTTP请求 (" + this.length + " 字节):");
                                console.log(data.substring(0, data.length));
                            }
                        } catch (e) {
                            console.log("[-] SSL_write 数据读取失败: " + e.message);
                        }
                    }
                }
            });
            console.log("[+] SSL_write Hook成功");
        }
        
        if (sslFunctions.SSL_read) {
            Interceptor.attach(sslFunctions.SSL_read, {
                onEnter: function(args) {
                    this.ssl = args[0];
                    this.buffer = args[1];
                    this.maxLength = args[2].toInt32();
                },
                onLeave: function(retval) {
                    var bytesRead = retval.toInt32();
                    if (bytesRead > 0 && bytesRead < 10000) {
                        try {
                            var data = this.buffer.readUtf8String(bytesRead);
                            if (data && data.indexOf("HTTP") !== -1) {
                                console.log("[!] SSL_read 捕获HTTP响应 (" + bytesRead + " 字节):");
                                console.log(data.substring(0, data.length));
                            }
                        } catch (e) {
                            console.log("[-] SSL_read 数据读取失败: " + e.message);
                        }
                    }
                }
            });
            console.log("[+] SSL_read Hook成功");
        }
        
        hookInstalled = true;
        console.log("[+] SSL Hook安装完成！");
        
    } catch (e) {
        console.log("[-] 安装SSL Hook失败: " + e.message);
        console.log("[-] 错误堆栈: " + e.stack);
    }
}

// 主执行逻辑
console.log("[+] 开始执行DLL检测...");

// 1. 立即检查是否已经加载了DLL
if (!checkExistingDLL()) {
    console.log("[+] libssl-1_1.dll 尚未加载，设置监听器");
    // 2. 如果没有加载，设置监听器
    setupModuleLoadListener();
} else {
    console.log("[+] libssl-1_1.dll 已经加载并Hook完成");
}

// 3. 设置定期检查（作为备用机制，频率很低）
var checkCount = 0;
var maxChecks = 100; // 最多检查100次
var checkInterval = setInterval(function() {
    checkCount++;
    
    if (hookInstalled) {
        console.log("[+] Hook已完成，停止定期检查");
        clearInterval(checkInterval);
        return;
    }
    
    if (checkCount >= maxChecks) {
        console.log("[-] 达到最大检查次数，停止检查");
        clearInterval(checkInterval);
        return;
    }
    
    checkAndHookDLL();
}, 100); // 每100ms检查一次

console.log("[+] DLL检测Hook脚本初始化完成");
