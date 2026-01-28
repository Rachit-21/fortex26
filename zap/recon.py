class Recon:
    def __init__(self, zap_client):
        self.zap = zap_client.zap

    def spider(self, target_url):
        print(f"Spidering {target_url}...")
        self.zap.spider.scan(target_url)
        # TODO: Add logic to wait for spider to complete
