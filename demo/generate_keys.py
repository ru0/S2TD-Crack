#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生成RSA公私钥对的脚本
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keys():
    """生成RSA密钥对并保存到文件"""
    print("正在生成RSA密钥对...")
    
    # 生成私钥 (2048位)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # 获取公钥
    public_key = private_key.public_key()
    
    # 序列化私钥
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # 序列化公钥
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # 保存私钥
    with open('private_key.pem', 'wb') as f:
        f.write(private_pem)
    print("私钥已保存到: private_key.pem")
    
    # 保存公钥
    with open('public_key.pem', 'wb') as f:
        f.write(public_pem)
    print("公钥已保存到: public_key.pem")
    
    print("RSA密钥对生成完成！")

if __name__ == "__main__":
    generate_rsa_keys()
