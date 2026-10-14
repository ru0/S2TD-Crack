## 客户端双向证书+报文加密破解


openssl x509 -inform der -in cert_52BFFC40F80002868FD599F03C66F84A98737EBB.der -out cert.crt


curl -v --cert cert.crt --key tmpvzd2agdz.pem https://lic.megacave.com/api/v2/get-csrf-token


C:\Users\test\Desktop\thonny-4.1.7-windows-portable\python.exe realtime_process_monitor.py S2TD_Converter_v.2.2_CN_MT.exe dll_detection_hook.js


要将 CER 证书和私钥（KEY）转换为 P12（PKCS#12）格式，然后导入到系统。

openssl pkcs12 -export -in certificate.cer -inkey private.key -out output.p12 -name "My Certificate"
