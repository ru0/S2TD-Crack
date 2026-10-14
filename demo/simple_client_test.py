#!/usr/bin/env python3
"""
简化的客户端证书测试程序
专门测试 https://lic.megacave.com/api/v2/get-csrf-token
"""

import requests
import os
import json
from urllib3.exceptions import InsecureRequestWarning

# 禁用 SSL 警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def test_csrf_token():
    """测试获取CSRF令牌"""
    
    # 证书文件路径
    cert_path = "cert.pem"
    key_path = "tmpvzd2agdz.pem"
    
    # 检查证书文件
    if not os.path.exists(cert_path):
        print(f"❌ 证书文件不存在: {cert_path}")
        return False
    if not os.path.exists(key_path):
        print(f"❌ 私钥文件不存在: {key_path}")
        return False
    
    print("🔐 客户端证书测试")
    print(f"证书: {cert_path}")
    print(f"私钥: {key_path}")
    print()
    
    # 目标URL
    url = "https://lic.megacave.com/api/v2/get-csrf-token"
    print(f"🌐 测试URL: {url}")
    
    try:
        # 发送请求
        response = requests.get(
            url,
            cert=(cert_path, key_path),
            verify=False,  # 跳过SSL验证
            timeout=30
        )
        
        print(f"✅ 请求成功!")
        print(f"状态码: {response.status_code}")
        print(f"响应头: {response.headers}")
        
        print(f"\n响应内容:")
        print(response.text)
        
        return True
        
    except requests.exceptions.SSLError as e:
        print(f"❌ SSL错误: {e}")
        return False
    except requests.exceptions.ConnectionError as e:
        print(f"❌ 连接错误: {e}")
        return False
    except requests.exceptions.Timeout as e:
        print(f"❌ 超时错误: {e}")
        return False
    except Exception as e:
        print(f"❌ 其他错误: {e}")
        return False

if __name__ == "__main__":
    success = test_csrf_token()
    exit(0 if success else 1)
