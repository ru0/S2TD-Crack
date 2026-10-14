/**
 * Frida模块加载监控脚本
 * 简化版本，只监控模块加载情况
 */

console.log("=== Frida模块加载监控 ===");

// 检查基本环境
console.log("1. 检查Frida环境:");
console.log("   Process: " + typeof Process);
console.log("   Module: " + typeof Module);

if (typeof Process !== 'undefined') {
    console.log("   Process.arch: " + Process.arch);
    console.log("   Process.platform: " + Process.platform);
    console.log("   Process.id: " + Process.id);
}

// 获取系统模块信息（修复findBaseAddress问题）
if (typeof Module !== 'undefined' && typeof Process !== 'undefined') {
    console.log("\n2. 检查系统模块:");
    try {
        // 使用Process.enumerateModules()替代Module.findBaseAddress
        const modules = Process.enumerateModules();
        const kernel32 = modules.find(m => m.name.toLowerCase() === "kernel32.dll");
        
        if (kernel32) {
            console.log("   kernel32.dll: " + kernel32.base + " (size: " + kernel32.size + ")");
            
            // 使用更兼容的方法获取导出函数
            let loadLibraryW = null;
            let loadLibraryA = null;
            
            try {
                // 方法1: 尝试使用Module.getExportByName
                if (typeof Module.getExportByName === 'function') {
                    loadLibraryW = Module.getExportByName("kernel32.dll", "LoadLibraryW");
                    loadLibraryA = Module.getExportByName("kernel32.dll", "LoadLibraryA");
                }
                // 方法2: 尝试使用Module.findExportByName
                else if (typeof Module.findExportByName === 'function') {
                    loadLibraryW = Module.findExportByName("kernel32.dll", "LoadLibraryW");
                    loadLibraryA = Module.findExportByName("kernel32.dll", "LoadLibraryA");
                }
                // 方法3: 使用模块的exports属性
                else {
                    const kernel32Exports = kernel32.enumerateExports();
                    const loadLibWExport = kernel32Exports.find(exp => exp.name === "LoadLibraryW");
                    const loadLibAExport = kernel32Exports.find(exp => exp.name === "LoadLibraryA");
                    loadLibraryW = loadLibWExport ? loadLibWExport.address : null;
                    loadLibraryA = loadLibAExport ? loadLibAExport.address : null;
                }
            } catch (exportError) {
                console.log("   获取导出函数时出错: " + exportError.message);
            }
            
            console.log("   LoadLibraryW: " + (loadLibraryW || "未找到"));
            console.log("   LoadLibraryA: " + (loadLibraryA || "未找到"));
        } else {
            console.log("   未找到kernel32.dll模块");
        }
    } catch (e) {
        console.log("   模块检查错误: " + e.message);
    }
}

// 列出当前已加载的模块
if (typeof Process !== 'undefined') {
    console.log("\n3. 当前已加载的模块:");
    try {
        const modules = Process.enumerateModules();
        console.log("   总共加载了 " + modules.length + " 个模块");
        
        // 显示全部模块
        console.log("   全部模块:");
        for (let i = 0; i < modules.length; i++) {
            const module = modules[i];
            console.log("   [" + (i+1) + "] " + module.name + " @ " + module.base);
        }
        
        // 查找特定类型的模块
        // const pythonModules = modules.filter(m => 
        //     m.name.toLowerCase().includes("python") || 
        //     m.name.toLowerCase().includes(".pyd") ||
        //     m.name.toLowerCase().includes(".dll")
        // );
        
        // if (pythonModules.length > 0) {
        //     console.log("\n   发现Python相关模块:");
        //     pythonModules.forEach((module, index) => {
        //         console.log("   [Python-" + (index+1) + "] " + module.name + " @ " + module.base);
        //     });
        // }
        
    } catch (e) {
        console.log("   枚举模块错误: " + e.message);
    }
}

// 设置模块加载监控（不做hook处理）
console.log("\n4. 设置模块加载监控...");

// 获取导出函数的兼容性函数
function getExportAddress(moduleName, exportName) {
    try {
        // 方法1: 尝试使用Module.getExportByName
        if (typeof Module.getExportByName === 'function') {
            return Module.getExportByName(moduleName, exportName);
        }
        // 方法2: 尝试使用Module.findExportByName
        else if (typeof Module.findExportByName === 'function') {
            return Module.findExportByName(moduleName, exportName);
        }
        // 方法3: 使用模块的exports属性
        else {
            const modules = Process.enumerateModules();
            const targetModule = modules.find(m => m.name.toLowerCase() === moduleName.toLowerCase());
            if (targetModule) {
                const exports = targetModule.enumerateExports();
                const targetExport = exports.find(exp => exp.name === exportName);
                return targetExport ? targetExport.address : null;
            }
        }
    } catch (e) {
        console.log("   获取导出函数 " + exportName + " 失败: " + e.message);
        return null;
    }
    return null;
}

try {
    // 监控LoadLibraryW调用来检测新模块加载
    const loadLibraryW = getExportAddress("kernel32.dll", "LoadLibraryW");
    if (loadLibraryW) {
        Interceptor.attach(loadLibraryW, {
            onEnter: function(args) {
                try {
                    const path = Memory.readUtf16String(args[0]);
                    if (path) {
                        console.log("[模块加载] " + path);
                    }
                } catch (e) {
                    console.log("[模块加载] 无法读取路径: " + e.message);
                }
            }
        });
        console.log("   LoadLibraryW监控已设置");
    } else {
        console.log("   LoadLibraryW函数未找到，跳过监控");
    }
    
    // 监控LoadLibraryA调用
    const loadLibraryA = getExportAddress("kernel32.dll", "LoadLibraryA");
    if (loadLibraryA) {
        Interceptor.attach(loadLibraryA, {
            onEnter: function(args) {
                try {
                    const path = Memory.readUtf8String(args[0]);
                    if (path) {
                        console.log("[模块加载] " + path);
                    }
                } catch (e) {
                    console.log("[模块加载] 无法读取路径: " + e.message);
                }
            }
        });
        console.log("   LoadLibraryA监控已设置");
    } else {
        console.log("   LoadLibraryA函数未找到，跳过监控");
    }
    
    if (loadLibraryW || loadLibraryA) {
        console.log("   模块加载监控设置完成!");
    } else {
        console.log("   警告: 无法设置模块加载监控，所有导出函数都未找到");
    }
    
} catch (e) {
    console.log("   监控设置失败: " + e.message);
}

console.log("\n=== 监控已启动，等待模块加载事件 ===");
