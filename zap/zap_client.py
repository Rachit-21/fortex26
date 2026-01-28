import time
from zapv2 import ZAPv2


class ZAPClient:
    def __init__(
        self,
        zap_proxy="http://127.0.0.1:8080",
        api_key=None,
        timeout=60,
    ):
        """
        ZAP API Client Wrapper
        """
        self.zap = ZAPv2(
            apikey=api_key,
            proxies={
                "http": zap_proxy,
                "https": zap_proxy,
            },
        )
        self.timeout = timeout

    # ----------------------------
    # Spider / Crawl
    # ----------------------------
    def spider(self, target_url):
        print(f"[+] Starting spider on {target_url}")
        scan_id = self.zap.spider.scan(target_url)

        while int(self.zap.spider.status(scan_id)) < 100:
            print(f"    Spider progress: {self.zap.spider.status(scan_id)}%")
            time.sleep(2)

        print("[+] Spider completed")

    # ----------------------------
    # Passive Scan Wait
    # ----------------------------
    def wait_for_passive_scan(self):
        print("[+] Waiting for passive scan to finish")
        while int(self.zap.pscan.records_to_scan) > 0:
            print(
                f"    Records left: {self.zap.pscan.records_to_scan}"
            )
            time.sleep(2)
        print("[+] Passive scan completed")

    # ----------------------------
    # Get All URLs Discovered
    # ----------------------------
    def get_urls(self):
        urls = self.zap.core.urls()
        return list(set(urls))

    # ----------------------------
    # Get HTTP Messages (Requests)
    # ----------------------------
    def get_http_messages(self):
        """
        Returns raw HTTP messages ZAP has seen
        """
        messages = self.zap.core.messages()
        return messages

    # ----------------------------
    # Extract Endpoints & Parameters
    # ----------------------------
    def extract_attack_surface(self):
        """
        Extract endpoints and parameters from ZAP history
        """
        attack_surface = []

        messages = self.get_http_messages()

        for msg in messages:
            request_header = msg.get("requestHeader", "")
            request_body = msg.get("requestBody", "")

            # Extract URL
            url_line = request_header.split("\n")[0]
            try:
                method, path, _ = url_line.split(" ")
            except ValueError:
                continue

            params = []

            # Query params
            if "?" in path:
                query = path.split("?")[1]
                for p in query.split("&"):
                    params.append(p.split("=")[0])

            attack_surface.append(
                {
                    "method": method,
                    "path": path.split("?")[0],
                    "parameters": list(set(params)),
                    "raw_request": request_header + "\n" + request_body,
                }
            )

        return attack_surface

    # ----------------------------
    # Clear ZAP Session
    # ----------------------------
    def reset_session(self):
        print("[+] Resetting ZAP session")
        self.zap.core.new_session(overwrite=True)
