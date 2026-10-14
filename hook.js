
// libcrypto-1_1.dll 加密函数Hook脚本
console.log("[+] libcrypto-1_1.dll Crypto Hook");

var cryptoData = [];
var capturedKeys = [];


// libcrypto-1_1.dll 加密函数Hook
function patchCryptoMemory() {
    try {
        var libcrypto = Process.findModuleByName("libcrypto-1_1.dll");
        if (!libcrypto) {
            console.log("[-] libcrypto-1_1.dll not found");
            return false;
        }
        
        console.log("[+] 找到 libcrypto-1_1.dll: " + libcrypto.base);
        
        var exports = libcrypto.enumerateExports();
        console.log("[+] 枚举到 " + exports.length + " 个加密导出函数");
        
        // AES函数地址
        var aesEncrypt = null;
        var aesDecrypt = null;
        var evpEncryptInit = null;
        var evpEncryptUpdate = null;
        var evpEncryptFinal = null;
        var evpDecryptInit = null;
        var evpDecryptUpdate = null;
        var evpDecryptFinal = null;
        
        // RSA函数地址
        var rsaPublicEncrypt = null;
        var rsaPrivateDecrypt = null;
        var rsaPrivateEncrypt = null;
        var rsaPublicDecrypt = null;
        var evpPkeyEncrypt = null;
        var evpPkeyDecrypt = null;
        
        // 查找AES函数
        var aesEncryptFunc = exports.find(function(exp) { return exp.name === "AES_encrypt"; });
        var aesDecryptFunc = exports.find(function(exp) { return exp.name === "AES_decrypt"; });
        var evpEncInitFunc = exports.find(function(exp) { return exp.name === "EVP_EncryptInit_ex"; });
        var evpEncUpdateFunc = exports.find(function(exp) { return exp.name === "EVP_EncryptUpdate"; });
        var evpEncFinalFunc = exports.find(function(exp) { return exp.name === "EVP_EncryptFinal_ex"; });
        var evpDecInitFunc = exports.find(function(exp) { return exp.name === "EVP_DecryptInit_ex"; });
        var evpDecUpdateFunc = exports.find(function(exp) { return exp.name === "EVP_DecryptUpdate"; });
        var evpDecFinalFunc = exports.find(function(exp) { return exp.name === "EVP_DecryptFinal_ex"; });
        
        // 查找RSA函数
        var rsaPubEncFunc = exports.find(function(exp) { return exp.name === "RSA_public_encrypt"; });
        var rsaPrivDecFunc = exports.find(function(exp) { return exp.name === "RSA_private_decrypt"; });
        var rsaPrivEncFunc = exports.find(function(exp) { return exp.name === "RSA_private_encrypt"; });
        var rsaPubDecFunc = exports.find(function(exp) { return exp.name === "RSA_public_decrypt"; });
        var evpPkeyEncFunc = exports.find(function(exp) { return exp.name === "EVP_PKEY_encrypt"; });
        var evpPkeyDecFunc = exports.find(function(exp) { return exp.name === "EVP_PKEY_decrypt"; });
        
        // 查找DES函数
        var desEncryptFunc = exports.find(function(exp) { return exp.name === "DES_encrypt1"; });
        var desDecryptFunc = exports.find(function(exp) { return exp.name === "DES_decrypt1"; });
        var des3EncryptFunc = exports.find(function(exp) { return exp.name === "DES_encrypt3"; });
        var des3DecryptFunc = exports.find(function(exp) { return exp.name === "DES_decrypt3"; });
        
        // 其他加密函数已移除 (MD5, SHA1, SHA256, HMAC)
        
        // 设置函数地址
        if (aesEncryptFunc) aesEncrypt = aesEncryptFunc.address;
        if (aesDecryptFunc) aesDecrypt = aesDecryptFunc.address;
        if (evpEncInitFunc) evpEncryptInit = evpEncInitFunc.address;
        if (evpEncUpdateFunc) evpEncryptUpdate = evpEncUpdateFunc.address;
        if (evpEncFinalFunc) evpEncryptFinal = evpEncFinalFunc.address;
        if (evpDecInitFunc) evpDecryptInit = evpDecInitFunc.address;
        if (evpDecUpdateFunc) evpDecryptUpdate = evpDecUpdateFunc.address;
        if (evpDecFinalFunc) evpDecryptFinal = evpDecFinalFunc.address;
        
        if (rsaPubEncFunc) rsaPublicEncrypt = rsaPubEncFunc.address;
        if (rsaPrivDecFunc) rsaPrivateDecrypt = rsaPrivDecFunc.address;
        if (rsaPrivEncFunc) rsaPrivateEncrypt = rsaPrivEncFunc.address;
        if (rsaPubDecFunc) rsaPublicDecrypt = rsaPubDecFunc.address;
        if (evpPkeyEncFunc) evpPkeyEncrypt = evpPkeyEncFunc.address;
        if (evpPkeyDecFunc) evpPkeyDecrypt = evpPkeyDecFunc.address;
        
        // 设置DES函数地址
        var desEncrypt = desEncryptFunc ? desEncryptFunc.address : null;
        var desDecrypt = desDecryptFunc ? desDecryptFunc.address : null;
        var des3Encrypt = des3EncryptFunc ? des3EncryptFunc.address : null;
        var des3Decrypt = des3DecryptFunc ? des3DecryptFunc.address : null;
        
        var aesCount = [aesEncrypt, aesDecrypt, evpEncryptInit, evpEncryptUpdate, evpEncryptFinal, evpDecryptInit, evpDecryptUpdate, evpDecryptFinal].filter(function(f) { return f; }).length;
        var rsaCount = [rsaPublicEncrypt, rsaPrivateDecrypt, rsaPrivateEncrypt, rsaPublicDecrypt, evpPkeyEncrypt, evpPkeyDecrypt].filter(function(f) { return f; }).length;
        var desCount = [desEncrypt, desDecrypt, des3Encrypt, des3Decrypt].filter(function(f) { return f; }).length;
        console.log("[+] 找到 " + aesCount + "/8 个AES函数, " + rsaCount + "/6 个RSA函数, " + desCount + "/4 个DES函数");
        
        // Hook AES_encrypt
        if (aesEncrypt) {
            try {
                Interceptor.attach(aesEncrypt, {
                    onEnter: function(args) {
                        console.log("[*] AES_encrypt 被调用");
                    }
                });
                console.log("[+] AES_encrypt Hook成功");
            } catch (e) {
                console.log("[-] AES_encrypt Hook失败: " + e.message);
            }
        }
        
        // Hook AES_decrypt
        if (aesDecrypt) {
            try {
                Interceptor.attach(aesDecrypt, {
                    onEnter: function(args) {
                        console.log("[*] AES_decrypt 被调用");
                    }
                });
                console.log("[+] AES_decrypt Hook成功");
            } catch (e) {
                console.log("[-] AES_decrypt Hook失败: " + e.message);
            }
        }
        
        // Hook EVP_EncryptUpdate (高级AES加密)
        if (evpEncryptUpdate) {
            try {
                Interceptor.attach(evpEncryptUpdate, {
                    onEnter: function(args) {
                        console.log("[*] EVP_EncryptUpdate 被调用");
                    }
                });
                console.log("[+] EVP_EncryptUpdate Hook成功");
            } catch (e) {
                console.log("[-] EVP_EncryptUpdate Hook失败: " + e.message);
            }
        }
        
        // Hook EVP_DecryptUpdate (高级AES解密)
        if (evpDecryptUpdate) {
            try {
                Interceptor.attach(evpDecryptUpdate, {
                    onEnter: function(args) {
                        console.log("[*] EVP_DecryptUpdate 被调用");
                    }
                });
                console.log("[+] EVP_DecryptUpdate Hook成功");
            } catch (e) {
                console.log("[-] EVP_DecryptUpdate Hook失败: " + e.message);
            }
        }
        
        // Hook RSA_public_encrypt
        if (rsaPublicEncrypt) {
            try {
                Interceptor.attach(rsaPublicEncrypt, {
                    onEnter: function(args) {
                        console.log("[*] RSA_public_encrypt 被调用");
                    }
                });
                console.log("[+] RSA_public_encrypt Hook成功");
            } catch (e) {
                console.log("[-] RSA_public_encrypt Hook失败: " + e.message);
            }
        }
        
        // Hook RSA_private_decrypt
        if (rsaPrivateDecrypt) {
            try {
                Interceptor.attach(rsaPrivateDecrypt, {
                    onEnter: function(args) {
                        console.log("[*] RSA_private_decrypt 被调用");
                    }
                });
                console.log("[+] RSA_private_decrypt Hook成功");
            } catch (e) {
                console.log("[-] RSA_private_decrypt Hook失败: " + e.message);
            }
        }
        
        // Hook EVP_PKEY_encrypt (高级RSA加密)
        if (evpPkeyEncrypt) {
            try {
                Interceptor.attach(evpPkeyEncrypt, {
                    onEnter: function(args) {
                        console.log("[*] EVP_PKEY_encrypt 被调用");
                    }
                });
                console.log("[+] EVP_PKEY_encrypt Hook成功");
            } catch (e) {
                console.log("[-] EVP_PKEY_encrypt Hook失败: " + e.message);
            }
        }
        
        // Hook EVP_PKEY_decrypt (高级RSA解密)
        if (evpPkeyDecrypt) {
            try {
                Interceptor.attach(evpPkeyDecrypt, {
                    onEnter: function(args) {
                        console.log("[*] EVP_PKEY_decrypt 被调用");
                    }
                });
                console.log("[+] EVP_PKEY_decrypt Hook成功");
            } catch (e) {
                console.log("[-] EVP_PKEY_decrypt Hook失败: " + e.message);
            }
        }
        
        // Hook RSA_private_encrypt
        if (rsaPrivateEncrypt) {
            try {
                Interceptor.attach(rsaPrivateEncrypt, {
                    onEnter: function(args) {
                        this.flen = args[0].toInt32(); // int flen - 明文长度
                        this.from = args[1];           // const unsigned char *from - 明文指针
                        this.to = args[2];             // unsigned char *to - 密文缓冲区
                        this.rsa = args[3];            // RSA *rsa - RSA密钥结构体
                        this.padding = args[4].toInt32(); // int padding - 填充模式
                        
                        // 解析填充模式
                        var paddingName = "UNKNOWN";
                        switch(this.padding) {
                            case 1: paddingName = "RSA_PKCS1_PADDING"; break;
                            case 3: paddingName = "RSA_NO_PADDING"; break;
                            case 4: paddingName = "RSA_PKCS1_OAEP_PADDING"; break;
                            case 6: paddingName = "RSA_SSLV23_PADDING"; break;
                        }
                        
                        console.log("[*] RSA_private_encrypt 被调用: flen=" + this.flen + ", padding=" + paddingName);
                        
                        // 显示加密前的明文
                        try {
                            if (this.from && !this.from.isNull() && this.flen > 0 && this.flen < 10000) {
                                var plaintext = this.from.readByteArray(this.flen);
                                if (plaintext) {
                                    console.log("[+] 加密前明文 (" + this.flen + "字节):");
                                    console.log(hexdump(plaintext, { ansi: true }));
                                    
                                    // 额外调试信息
                                    console.log("[DEBUG] 明文指针地址: " + this.from);
                                    console.log("[DEBUG] 密文缓冲区地址: " + this.to);
                                }
                            }
                        } catch (e) {
                            console.log("[-] 读取明文错误: " + e.message);
                        }
                    },
                    onLeave: function(retval) {
                        try {
                            var encryptedLen = retval.toInt32();
                            console.log("[*] RSA_private_encrypt 返回: " + encryptedLen + " 字节 (" + (encryptedLen > 0 ? "成功" : "失败") + ")");
                            
                            // 显示加密后的密文
                            if (this.to && !this.to.isNull() && encryptedLen > 0) {
                                var ciphertext = this.to.readByteArray(encryptedLen);
                                if (ciphertext) {
                                    console.log("[+] 加密后密文 (" + encryptedLen + "字节):");
                                    console.log(hexdump(ciphertext, { ansi: true }));
                                    
                                    // 检查密文是否真的是加密数据
                                    var isLikelyEncrypted = true;
                                    var printableCount = 0;
                                    var bytes = new Uint8Array(ciphertext);
                                    
                                    for (var i = 0; i < Math.min(bytes.length, 100); i++) {
                                        if (bytes[i] >= 32 && bytes[i] <= 126) {
                                            printableCount++;
                                        }
                                    }
                                    
                                    var printableRatio = printableCount / Math.min(bytes.length, 100);
                                    if (printableRatio > 0.7) {
                                        console.log("[WARNING] 密文中可打印字符比例过高 (" + (printableRatio * 100).toFixed(1) + "%)，可能不是真正的加密数据！");
                                    }
                                    
                                    console.log("[DEBUG] 返回值: " + encryptedLen + ", 密文缓冲区大小: " + ciphertext.byteLength);
                                }
                            }
                        } catch (e) {
                            console.log("[-] 读取密文错误: " + e.message);
                        }
                    }
                });
                console.log("[+] RSA_private_encrypt Hook成功");
            } catch (e) {
                console.log("[-] RSA_private_encrypt Hook失败: " + e.message);
            }
        }
        
        // Hook RSA_public_decrypt
        if (rsaPublicDecrypt) {
            try {
                Interceptor.attach(rsaPublicDecrypt, {
                    onEnter: function(args) {
                        console.log("[*] RSA_public_decrypt 被调用");
                    }
                });
                console.log("[+] RSA_public_decrypt Hook成功");
            } catch (e) {
                console.log("[-] RSA_public_decrypt Hook失败: " + e.message);
            }
        }
        
        // Hook DES_encrypt1
        if (desEncrypt) {
            try {
                Interceptor.attach(desEncrypt, {
                    onEnter: function(args) {
                        console.log("[*] DES_encrypt1 被调用");
                    }
                });
                console.log("[+] DES_encrypt1 Hook成功");
            } catch (e) {
                console.log("[-] DES_encrypt1 Hook失败: " + e.message);
            }
        }
        
        // Hook DES_decrypt1
        if (desDecrypt) {
            try {
                Interceptor.attach(desDecrypt, {
                    onEnter: function(args) {
                        console.log("[*] DES_decrypt1 被调用");
                    }
                });
                console.log("[+] DES_decrypt1 Hook成功");
            } catch (e) {
                console.log("[-] DES_decrypt1 Hook失败: " + e.message);
            }
        }
        
        // Hook DES_encrypt3 (3DES加密)
        if (des3Encrypt) {
            try {
                Interceptor.attach(des3Encrypt, {
                    onEnter: function(args) {
                        console.log("[*] DES_encrypt3 被调用");
                    }
                });
                console.log("[+] DES_encrypt3 Hook成功");
            } catch (e) {
                console.log("[-] DES_encrypt3 Hook失败: " + e.message);
            }
        }
        
        // Hook DES_decrypt3 (3DES解密)
        if (des3Decrypt) {
            try {
                Interceptor.attach(des3Decrypt, {
                    onEnter: function(args) {
                        console.log("[*] DES_decrypt3 被调用");
                    }
                });
                console.log("[+] DES_decrypt3 Hook成功");
            } catch (e) {
                console.log("[-] DES_decrypt3 Hook失败: " + e.message);
            }
        }
        
        // MD5, SHA1, SHA256, HMAC 相关函数已移除，只保留加解密相关函数
        
        return true;
        
    } catch (e) {
        console.log("[-] patchCryptoMemory 执行错误: " + e.message);
        console.log("[-] 错误堆栈: " + e.stack);
        return false;
    }
}

// 启动Hook
setTimeout(function() {
    console.log("[+] 启动加密Hook...");
    
    try {
        var cryptoSuccess = patchCryptoMemory();
        
        if (cryptoSuccess) {
            console.log("[+] 加密Hook安装成功");
        } else {
            console.log("[-] 加密Hook安装失败");
        }
        
        if (cryptoSuccess) {
            setInterval(function() {
                var cryptoCount = cryptoData.length;
                var keyCount = capturedKeys.length;
                if (cryptoCount > 0 || keyCount > 0) {
                    console.log("[+] 已捕获 加密数据: " + cryptoCount + " 项, 密钥: " + keyCount + " 个");
                }
            }, 30000);
        }
    } catch (error) {
        console.log("[-] 启动错误: " + error.message);
    }
}, 2000);

// 导出捕获的数据函数
function exportCapturedData() {
    return {
        crypto_data: cryptoData,
        captured_keys: capturedKeys,
        total_crypto: cryptoData.length,
        total_keys: capturedKeys.length,
        export_time: new Date().toISOString()
    };
}

// 清空捕获的数据
function clearCapturedData() {
    cryptoData.length = 0;
    capturedKeys.length = 0;
    console.log("[+] 已清空所有捕获的数据");
}

// 打印捕获的密钥
function printCapturedKeys(count) {
    count = count || 5;
    console.log("[+] 最近 " + count + " 个捕获的密钥:");
    var recent = capturedKeys.slice(-count);
    recent.forEach(function(item, index) {
        console.log("--- 密钥 " + (index + 1) + " ---");
        console.log("类型: " + item.type);
        console.log("大小: " + (item.size || "未知") + " 字节");
        console.log("时间: " + new Date(item.timestamp).toLocaleString());
        if (item.data) {
            console.log("密钥数据:");
            console.log(hexdump(item.data, { ansi: true }));
        }
        console.log("");
    });
}

// 打印最近的加密数据
function printRecentCryptoData(count) {
    count = count || 5;
    console.log("[+] 最近 " + count + " 条加密数据:");
    var recent = cryptoData.slice(-count);
    recent.forEach(function(item, index) {
        console.log("--- 项目 " + (index + 1) + " ---");
        console.log("类型: " + item.type);
        console.log("大小: " + (item.size || "未知") + " 字节");
        console.log("时间: " + new Date(item.timestamp).toLocaleString());
        if (item.data) {
            console.log("数据:");
            console.log(hexdump(item.data, { ansi: true }));
        }
        console.log("");
    });
}
