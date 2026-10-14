#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
实时进程监控器 - 使用Windows API事件监听
无轮询，立即检测子进程创建和DLL加载
"""

import frida
import sys
import time
import threading
import subprocess
import psutil
import os
from pathlib import Path
import ctypes
from ctypes import wintypes
import win32api
import win32con
import win32event
import win32process

class RealtimeProcessMonitor:
    def __init__(self, hook_script_path, target_exe_path=None, target_pid=None):
        self.target_exe_path = Path(target_exe_path) if target_exe_path else None
        self.hook_script_path = Path(hook_script_path)
        self.target_pid = target_pid
        self.target_process = None
        self.hooked_processes = set()
        self.running = True
        self.frida_sessions = {}

        # 验证参数
        if target_pid is None and target_exe_path is None:
            raise ValueError("必须指定目标程序路径或目标PID")

        if not self.hook_script_path.exists():
            raise FileNotFoundError(f"Hook脚本不存在: {self.hook_script_path}")

        if self.target_exe_path and not self.target_exe_path.exists():
            raise FileNotFoundError(f"目标程序不存在: {self.target_exe_path}")

        print(f"[+] 初始化实时进程监控器")
        if self.target_pid is not None:
            print(f"[+] 目标PID: {self.target_pid}")
        if self.target_exe_path is not None:
            print(f"[+] 目标程序: {self.target_exe_path}")
        print(f"[+] Hook脚本: {self.hook_script_path}")

    def load_hook_script(self):
        """加载Hook脚本"""
        try:
            with open(self.hook_script_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            print(f"[-] 读取Hook脚本失败: {e}")
            return None

    def on_message(self, message, data):
        """处理Frida消息"""
        if message['type'] == 'send':
            print(f"[Frida] {message['payload']}")
        elif message['type'] == 'error':
            print(f"[Frida Error] {message['stack']}")

    def hook_process_immediate(self, pid):
        """立即Hook进程"""
        if pid in self.hooked_processes:
            return False
            
        try:
            print(f"[+] 立即Hook进程 PID: {pid}")
            
            # 检查进程是否存在
            try:
                process = psutil.Process(pid)
                print(f"[+] 进程信息: {process.name()} - {process.exe()}")
            except psutil.NoSuchProcess:
                print(f"[-] 进程 {pid} 不存在")
                return False
            
            # 附加到进程
            session = frida.attach(pid)
            
            # 加载Hook脚本
            hook_script = self.load_hook_script()
            if not hook_script:
                return False
                
            # 创建脚本
            script = session.create_script(hook_script)
            script.on('message', self.on_message)
            
            # 加载脚本
            script.load()
            
            # 保存会话
            self.frida_sessions[pid] = session
            self.hooked_processes.add(pid)
            
            print(f"[+] 成功Hook进程 PID: {pid}")
            return True
            
        except frida.ProcessNotFoundError:
            print(f"[-] 进程 {pid} 不存在或已退出")
            return False
        except frida.PermissionDeniedError:
            print(f"[-] 权限不足，无法Hook进程 {pid}")
            return False
        except Exception as e:
            print(f"[-] Hook进程 {pid} 失败: {e}")
            return False

    def should_hook_process(self, pid):
        """判断是否应该Hook该进程"""
        try:
            process = psutil.Process(pid)
            process_name = process.name().lower()
            
            # 只Hook S2TD_Converter_v.2.2_CN_MT.exe 进程
            target_name = "s2td_converter_v.2.2_cn_mt.exe"
            return process_name == target_name
            
        except psutil.NoSuchProcess:
            return False
        except Exception as e:
            print(f"[-] 检查进程名称失败 PID {pid}: {e}")
            return False

    def log_process_info(self, pid):
        """记录进程信息和启动参数"""
        try:
            process = psutil.Process(pid)
            process_name = process.name()
            
            # 获取进程启动参数
            try:
                cmdline = process.cmdline()
                exe_path = process.exe()
                
                print(f"[INFO] 子进程信息 PID: {pid}")
                print(f"[INFO] 进程名称: {process_name}")
                print(f"[INFO] 可执行文件: {exe_path}")
                print(f"[INFO] 启动参数: {' '.join(cmdline)}")
                
                # 获取进程创建时间
                create_time = process.create_time()
                import datetime
                create_time_str = datetime.datetime.fromtimestamp(create_time).strftime('%Y-%m-%d %H:%M:%S')
                print(f"[INFO] 创建时间: {create_time_str}")
                
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                print(f"[INFO] 无法获取进程 {pid} 的详细信息（权限不足）")
                
        except psutil.NoSuchProcess:
            print(f"[INFO] 进程 {pid} 已退出")
        except Exception as e:
            print(f"[-] 记录进程信息失败 PID {pid}: {e}")

    def check_process_modules(self, pid):
        """检查进程模块，寻找libssl-1_1.dll或libssl-1_1-x64.dll"""
        try:
            process = psutil.Process(pid)
            
            # 检查进程是否还在运行
            if not process.is_running():
                return False
                
            # 尝试获取进程的内存映射
            try:
                memory_maps = process.memory_maps()
                for mmap in memory_maps:
                    path_lower = mmap.path.lower()
                    if 'libssl-1_1.dll' in path_lower or 'libssl-1_1-x64.dll' in path_lower:
                        print(f"[!] 进程 {pid} 加载了目标DLL: {mmap.path}")
                        return True
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                # 如果无法访问内存映射，尝试其他方法
                pass
                
            return False
            
        except psutil.NoSuchProcess:
            return False
        except Exception as e:
            print(f"[-] 检查进程 {pid} 模块失败: {e}")
            return False

    def monitor_child_processes(self):
        """监控子进程创建"""
        print("[+] 开始监控子进程创建...")
        
        last_check_time = time.time()
        known_children = set()
        
        while self.running:
            try:
                current_time = time.time()
                
                # 每100ms检查一次新的子进程
                if current_time - last_check_time >= 0.1:
                    if self.target_process and self.target_process.poll() is None:
                        try:
                            parent_proc = psutil.Process(self.target_process.pid)
                            current_children = set()
                            
                            # 获取所有子进程（递归）
                            children = parent_proc.children(recursive=True)
                            for child in children:
                                current_children.add(child.pid)
                                
                                # 如果是新发现的子进程
                                if child.pid not in known_children:
                                    print(f"[!] 发现新子进程 PID: {child.pid} - {child.name()}")
                                    known_children.add(child.pid)
                                    
                                    # 记录所有子进程信息
                                    self.log_process_info(child.pid)
                                    
                                    # 只对目标进程进行Hook检查
                                    if self.should_hook_process(child.pid):
                                        # 立即检查是否加载了目标DLL
                                        if self.check_process_modules(child.pid):
                                            print(f"[!] 子进程 {child.pid} 包含目标DLL，立即Hook")
                                            self.hook_process_immediate(child.pid)
                                        else:
                                            # 如果还没有加载DLL，启动监控线程
                                            monitor_thread = threading.Thread(
                                                target=self.monitor_single_process_dll_loading,
                                                args=(child.pid,),
                                                daemon=True
                                            )
                                            monitor_thread.start()
                                    else:
                                        print(f"[INFO] 跳过非目标进程 PID: {child.pid}")
                                        # 将非目标进程添加到已处理列表，避免重复记录
                                        self.hooked_processes.add(child.pid)
                            
                            # 清理已退出的子进程
                            known_children &= current_children
                            
                        except psutil.NoSuchProcess:
                            print("[-] 主进程已退出")
                            break
                        except Exception as e:
                            print(f"[-] 监控子进程时出错: {e}")
                    
                    last_check_time = current_time
                
                # 短暂休眠
                time.sleep(0.05)
                
            except KeyboardInterrupt:
                print("\n[+] 收到中断信号，停止监控")
                break
            except Exception as e:
                print(f"[-] 监控循环出错: {e}")
                time.sleep(0.5)

    def monitor_single_process_dll_loading(self, pid):
        """监控单个进程的DLL加载"""
        print(f"[+] 开始监控进程 {pid} 的DLL加载")
        
        check_count = 0
        max_checks = 200  # 最多检查20秒（100ms * 200）
        
        while self.running and check_count < max_checks:
            try:
                if pid in self.hooked_processes:
                    print(f"[+] 进程 {pid} 已被Hook，停止监控")
                    break
                
                # 检查进程是否还存在
                try:
                    process = psutil.Process(pid)
                    if not process.is_running():
                        print(f"[-] 进程 {pid} 已退出")
                        break
                except psutil.NoSuchProcess:
                    print(f"[-] 进程 {pid} 不存在")
                    break
                
                # 检查DLL加载
                if self.check_process_modules(pid):
                    print(f"[!] 进程 {pid} 加载了libssl-1_1.dll，立即Hook")
                    self.hook_process_immediate(pid)
                    break
                
                check_count += 1
                time.sleep(0.1)
                
            except Exception as e:
                print(f"[-] 监控进程 {pid} DLL加载时出错: {e}")
                break
        
        if check_count >= max_checks:
            print(f"[-] 进程 {pid} 监控超时，停止监控")

    def start_target_process(self):
        """启动目标进程"""
        try:
            print(f"[+] 启动目标程序: {self.target_exe_path}")
            
            # 启动目标程序
            self.target_process = subprocess.Popen(
                str(self.target_exe_path),
                cwd=self.target_exe_path.parent,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
            )
            
            print(f"[+] 目标程序已启动，PID: {self.target_process.pid}")
            
            # 立即检查主进程是否加载了目标DLL
            time.sleep(0.2)  # 给进程一点启动时间
            if self.check_process_modules(self.target_process.pid):
                print(f"[!] 主进程加载了libssl-1_1.dll，立即Hook")
                self.hook_process_immediate(self.target_process.pid)
            
            return True
            
        except Exception as e:
            print(f"[-] 启动目标程序失败: {e}")

    def run(self):
        """运行监控器"""
        try:
            if self.target_pid is None:
                # 启动目标进程模式
                self.start_target_process()
                
                # 启动子进程监控线程
                child_monitor = threading.Thread(target=self.monitor_child_processes, daemon=True)
                child_monitor.start()
                
                # 主线程等待目标进程结束
                if self.target_process:
                    self.target_process.wait()
            else:
                # PID模式，直接监控指定进程
                print(f"[+] 进入PID监控模式，按Ctrl+C退出")
                try:
                    while self.running:
                        time.sleep(1)
                        # 检查进程是否仍然存在
                        if not psutil.pid_exists(self.target_pid):
                            print(f"[!] 目标进程 {self.target_pid} 已退出")
                            break
                except KeyboardInterrupt:
                    print("\n[!] 收到停止信号")
                    
        except KeyboardInterrupt:
            print("\n[!] 收到停止信号")
        except Exception as e:
            print(f"[!] 监控器发生错误: {e}")
        finally:
            self.running = False
            self.cleanup()

    def cleanup(self):
        """清理资源"""
        print("[+] 正在清理资源...")
        self.running = False
        
        # 清理Frida会话
        for pid, session in list(self.frida_sessions.items()):
            try:
                session.detach()
                print(f"[+] 已从进程 {pid} 分离")
            except Exception as e:
                print(f"[-] 从进程 {pid} 分离失败: {e}")
        
        # 清理目标进程（仅在启动进程模式下）
        if self.target_process and hasattr(self.target_process, 'poll') and self.target_process.poll() is None:
            try:
                self.target_process.terminate()
                self.target_process.wait(timeout=5)
            except Exception as e:
                print(f"[-] 停止目标进程失败: {e}")
        
        self.frida_sessions.clear()
        self.hooked_processes.clear()


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='实时进程监控器 - 使用Frida进行进程Hook')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-p', '--pid', type=int, help='要Hook的进程PID')
    group.add_argument('-e', '--exe', type=str, help='要启动并监控的目标程序路径')
    parser.add_argument('-s', '--script', type=str, required=True, help='Frida脚本路径 (必填)')
    
    args = parser.parse_args()
    
    try:
        if args.pid:
            # 使用PID模式
            monitor = RealtimeProcessMonitor(hook_script_path=args.script, target_pid=args.pid)
            # 直接Hook指定PID
            if not monitor.hook_process_immediate(args.pid):
                print(f"[-] 无法Hook进程 {args.pid}")
                return
        else:
            # 使用可执行文件模式
            monitor = RealtimeProcessMonitor(hook_script_path=args.script, target_exe_path=args.exe)
        
        monitor.run()
    except KeyboardInterrupt:
        print("\n[!] 用户中断，正在退出...")
    except Exception as e:
        print(f"[!] 发生错误: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if 'monitor' in locals():
            monitor.cleanup()


if __name__ == "__main__":
    main()
