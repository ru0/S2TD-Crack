#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RSA加解密测试脚本
用于验证RSA公私钥加解密功能
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os
import base64
import time

# 硬编码的RSA私钥 (PEM格式)
PRIVATE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCdLC3jwfV+yfj8
GS3XXzNJ3+/K/ei/enKXLAgX25aQSalMEjJZAP4h89Ln53DkZU6pZCrLZwmDSsbY
X4IqsnFefc/yQ61HJ8MjzCObgsJVIcDtzLxaYRPGeOkT7hAyRzWmg38vtww0PVQk
PmEWUCIKtP1vK8b36T8UIXjAhOgkhnonww+ZaQp7ROU7v7+uxHkitL5hzwEA9e/4
Dknvsna3TmprqANwcvTawKN50rTVHbRYB4vvfOceN/rySQ2u0BImtCTR1+bZlpTR
KdbG0BdGBMUSq5N9eCVoW9z6giAIGn1ASFaZ3oLr6B2N/bZotSGQbNQPnbaAcgvX
PuPagnHfAgMBAAECggEADxAx4bcwGROwWjDrlM2Z88WTjMfi658Hpndg2zB/cJqu
sAy6aI9Qy947Y2BqEGmpLVDdTRs17TBYeFpG9mKdvOmf6V8VF1G3QRIKg5f3mgMf
I2tQzfSp2YazB+b0BG2QtcG6ic8oS0VpcAPOeD371TzdYS835YCkPACtOv5B5WYb
jk5K1FjkKMgApJocuPSXYVymsGl9/p9a3FHN1TStdB6BZ2jKvbwtpYZYJk1aTZbF
4HsoThy66qPjk3l86ZCM9O/D7D1W3R92vkxZQGjm8NA+YdexmVciT23MeuXqPNe4
6PwINjktQvYuxivwH0ib6hdg+u6tRAWrlDEXLrbQAQKBgQDOKQEK2b6RkuCFIb53
Z8Uc2dMh+7YuLyz3bDoh0MQ3sD+WjDnOKQzbIz4V0r04pUWaO8q/LdBS3xqS5sI2
YBspVhWleC0ydNllugnBMcNZjsPgrOurjimf8crINJpXQliRZ9vLRCv2xIFiMdnU
pq7Knk/s8yjgvY5oWHb9TBVJ3wKBgQDDK2TXMjTyYSamloe6rozmFr90KxJ9Tgqc
sPkJTrgC6wSoWMyjTbg2Qmm+vVE2IGTR4Iae+Xhd+5ZJDeNYd4b0P33lnIos+iTW
KpqUeKKiVpGA0pHpxHsqWK/Q9uFWyF4dionCeD6H6NHlH0zpvMcoKv+3nZdZTJJi
P2AIzQfYAQKBgQDJwzGE+ANcnx1izdqFK6aqjLfoG1t5qavdXisqaxGN2szwvr3X
+S7ezIf3fa64YG9U+c17+w9V+4kbWgGai8YpV1mJ/qplJhyZRVBEpjokTOeA3Fst
I82y/kVSWMDwQztA2x8tuMM6F6j0fAtO5e5M2FEqefN4t6tGjcWuMibniwKBgQCl
udldKpLvJjPNzZDfooyebL6SBGkk4fn86AHwN1nlkG9aDF1oZfyAhpCImPW3Anba
CNAHeksNcy9ARXzBiG2eRbPAH9btLlPNUEwGuxFOzDetriCc4my7nqdcx+a87FOO
vi8QZU6j1b011AhZiiWLJEgUQMtd1rmOl8YScxewAQKBgE5MPPoYTl6lC8Rq3p9g
Hmj/bSxfeH+xh6U5wIt6ZoZknkKFty92zMs3N7D6y+XNq5FlM6jxxmr291GqOiG+
CCmRKQtETGkoOKVO3jh9Jfm6JMy0IOesi9NN0hu2DODnvIg+ux+Mo/D/MDjeceH0
ZyYaCCVg4bLOrxfwKyCIyeWB
-----END PRIVATE KEY-----"""

# 硬编码的RSA公钥 (PEM格式)
PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnSwt48H1fsn4/Bkt118z
Sd/vyv3ov3pylywIF9uWkEmpTBIyWQD+IfPS5+dw5GVOqWQqy2cJg0rG2F+CKrJx
Xn3P8kOtRyfDI8wjm4LCVSHA7cy8WmETxnjpE+4QMkc1poN/L7cMND1UJD5hFlAi
CrT9byvG9+k/FCF4wIToJIZ6J8MPmWkKe0TlO7+/rsR5IrS+Yc8BAPXv+A5J77J2
t05qa6gDcHL02sCjedK01R20WAeL73znHjf68kkNrtASJrQk0dfm2ZaU0SnWxtAX
RgTFEquTfXglaFvc+oIgCBp9QEhWmd6C6+gdjf22aLUhkGzUD522gHIL1z7j2oJx
3wIDAQAB
-----END PUBLIC KEY-----"""

def load_private_key():
    """加载硬编码的私钥"""
    private_key = serialization.load_pem_private_key(
        PRIVATE_KEY_PEM.encode(),
        password=None
    )
    return private_key

def load_public_key():
    """加载硬编码的公钥"""
    public_key = serialization.load_pem_public_key(PUBLIC_KEY_PEM.encode())
    return public_key

def rsa_encrypt_decrypt_test():
    """RSA加解密测试"""
    print("=== RSA加解密测试 ===")
    
    # 测试数据
    plaintext = b"Hello, RSA Encryption Test!"
    print(f"原始明文: {plaintext.decode()}")
    print(f"明文长度: {len(plaintext)} 字节")
    print()
    
    try:
        # 加载硬编码的密钥
        private_key = load_private_key()
        public_key = load_public_key()
        
        # 1. 公钥加密，私钥解密
        print("1. 公钥加密 -> 私钥解密")
        ciphertext = public_key.encrypt(
            plaintext,
            padding.PKCS1v15()
        )
        print(f"密文长度: {len(ciphertext)} 字节")
        print(f"密文(base64): {base64.b64encode(ciphertext).decode()}")
        
        # 私钥解密
        decrypted = private_key.decrypt(
            ciphertext,
            padding.PKCS1v15()
        )
        print(f"解密结果: {decrypted.decode()}")
        print(f"解密成功: {plaintext == decrypted}")
        print()
        
        # 2. 私钥加密（签名），公钥解密（验证）
        print("2. 私钥加密 -> 公钥解密")
        # 注意：这里使用签名操作模拟私钥加密
        signature = private_key.sign(
            plaintext,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print(f"签名长度: {len(signature)} 字节")
        print(f"签名(base64): {base64.b64encode(signature).decode()}")
        
        # 公钥验证签名
        try:
            public_key.verify(
                signature,
                plaintext,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            print("签名验证成功")
        except Exception as e:
            print(f"签名验证失败: {e}")
        
    except ValueError as e:
        print(f"密钥格式错误: {e}")
        print("请检查硬编码的密钥是否正确！")
    except Exception as e:
        print(f"加解密过程出错: {e}")

if __name__ == "__main__":

    # 运行测试
    while True:
        rsa_encrypt_decrypt_test()
        time.sleep(5)
