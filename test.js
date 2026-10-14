// CryptoAPI函数列表 - 基于cryptsp.txt中实际存在的函数
var cryptoFunctions = [
    "CryptAcquireContextA",
    "CryptAcquireContextW", 
    "CryptContextAddRef",
    "CryptCreateHash",
    "CryptDecrypt",
    "CryptDeriveKey",
    "CryptDestroyHash",
    "CryptDestroyKey",
    "CryptDuplicateHash",
    "CryptDuplicateKey",
    "CryptEncrypt",
    "CryptEnumProviderTypesA",
    "CryptEnumProviderTypesW",
    "CryptEnumProvidersA",
    "CryptEnumProvidersW",
    "CryptExportKey",
    "CryptGenKey",
    "CryptGenRandom",
    "CryptGetDefaultProviderA",
    "CryptGetDefaultProviderW",
    "CryptGetHashParam",
    "CryptGetKeyParam",
    "CryptGetProvParam",
    "CryptGetUserKey",
    "CryptHashData",
    "CryptHashSessionKey",
    "CryptImportKey",
    "CryptReleaseContext",
    "CryptSetHashParam",
    "CryptSetKeyParam",
    "CryptSetProvParam",
    "CryptSetProviderA",
    "CryptSetProviderExA",
    "CryptSetProviderExW",
    "CryptSetProviderW",
    "CryptSignHashA",
    "CryptSignHashW",
    "CryptVerifySignatureA",
    "CryptVerifySignatureW"
];

// Hook函数
function hookCryptoFunction(moduleName, functionName) {
    console.log("[DEBUG] 开始Hook函数: " + functionName + " 从模块: " + moduleName);
    
    try {
        // 检查模块是否存在
        var module = null;
        var funcAddr = null;
        module = Process.getModuleByName(moduleName);
        // 查找函数地址
        console.log("[DEBUG] 正在查找函数导出: " + functionName);
        
        if (!funcAddr && module) {
            try {
                funcAddr = DebugSymbol.getFunctionByName(functionName);
                console.log("[+] 找到函数: " + functionName + " @ " + funcAddr);
            } catch (e) {
                console.log("[DEBUG] DebugSymbol.getFunctionByName失败: " + e.message);
            }
        }
        
        // 尝试附加拦截器
        console.log("[DEBUG] 正在附加Interceptor到地址: " + funcAddr);
        try {
            Interceptor.attach(funcAddr, {
                onEnter: function(args) {
                    console.log("[*] " + functionName + " 被调用");
                },
                
                onLeave: function(retval) {
                    var success = retval.toInt32();
                    console.log("[*] " + functionName + " 返回: " + (success ? "成功" : "失败"));
                }
            });
            console.log("[DEBUG] Interceptor附加成功");
            return true;
        } catch (attachError) {
            console.log("[DEBUG] Interceptor.attach失败: " + attachError.message);
            console.log("[DEBUG] 错误类型: " + attachError.name);
            return false;
        }
        
    } catch (e) {
        console.log("[-] Hook " + functionName + " 失败: " + e.message);
        console.log("[DEBUG] 错误详情 - 名称: " + e.name + ", 堆栈: " + e.stack);
    }
    return false;
}

// 检查模块中的导出函数
function listModuleExports(moduleName) {
    try {
        var module = Process.getModuleByName(moduleName);
        if (module) {
            console.log("[*] " + moduleName + " 导出的Crypt相关函数:");
            var exports = module.enumerateExports();
            var cryptExports = exports.filter(function(exp) {
                return exp.name && exp.name.toLowerCase().indexOf('crypt') !== -1;
            });
            
            cryptExports.forEach(function(exp) {
                console.log("  -> " + exp.name + " @ " + exp.address);
            });
            
            return cryptExports.length;
        }
    } catch (e) {
        console.log("[-] 无法枚举 " + moduleName + " 的导出函数: " + e.message);
    }
    return 0;
}

// 首先列出cryptsp.dll中实际存在的Crypt函数
console.log("\n[*] 检查cryptsp.dll中的Crypt相关导出函数:");
var cryptspCount = listModuleExports("crypt32.dll");

console.log("\n[*] 开始Hook CryptoAPI函数...");

// 优先Hook cryptsp.dll中的函数（因为已确认存在）
var hookedCount = 0;
var hookedFunctions = [];

cryptoFunctions.forEach(function(funcName) {
    // 避免重复Hook同一个函数
    if (hookedFunctions.indexOf(funcName) !== -1) {
        return;
    }
    
    // 只从cryptsp.dll中查找和Hook函数
    if (hookCryptoFunction("crypt32.dll", funcName)) {
        hookedCount++;
        hookedFunctions.push(funcName);
        console.log("[+] 成功Hook cryptsp.dll中的函数: " + funcName);
    } else {
        console.log("[-] cryptsp.dll中未找到函数: " + funcName);
    }
});

console.log("\n[+] 成功Hook了 " + hookedCount + "/" + cryptoFunctions.length + " 个cryptsp.dll中的函数");
console.log("[*] cryptsp.dll Hook初始化完成，等待函数调用...");