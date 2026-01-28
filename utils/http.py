import requests

class HTTPClient:
    def get(self, url, params=None):
        return requests.get(url, params=params)

    def post(self, url, data=None):
        return requests.post(url, data=data)
