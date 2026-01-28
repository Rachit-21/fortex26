from zapv2 import ZAPv2

ZAP_URL = "http://192.168.56.101:8080"
API_KEY = "changeme"

print("[+] Script started")
print(f"[+] Connecting to ZAP at {ZAP_URL}")

zap = ZAPv2(
    apikey=API_KEY,
    proxies={
        "http": ZAP_URL,
        "https": ZAP_URL
    }
)

print("[+] ZAP object created")

version = zap.core.version
print("[+] ZAP Version:", version)
