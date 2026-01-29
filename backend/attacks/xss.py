import requests
import urllib.parse
import copy

class XSSTester:
    def __init__(self, headers=None, proxies=None):
        self.headers = headers or {}
        self.proxies = proxies or {}
        self.payloads = [
            "<script>alert(1)</script>",
            "\" onmouseover=\"alert(1)",
            "javascript:alert(1)",
        ]

    def test_endpoint(self, endpoint):
        if isinstance(endpoint, dict):
            url = endpoint.get("url") or endpoint.get("path")
        else:
            url = endpoint

        if not url:
            return None

        print(f"[XSS] Testing {url}")
        
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        # Combine URL query params with explicit params from ZAP
        combined_params = copy.deepcopy(query_params)
        
        explicit_params = endpoint.get("parameters", [])
        if isinstance(explicit_params, list):
            for p in explicit_params:
                if p not in combined_params:
                    combined_params[p] = [""] # Initialize if missing

        if not combined_params:
            return []

        findings = []

        for param in combined_params.keys():
            for payload in self.payloads:
                # 1. Inject into URL query if present there
                if param in query_params:
                    new_query = copy.deepcopy(query_params)
                    new_query[param] = [payload]
                    new_query_string = urllib.parse.urlencode(new_query, doseq=True)
                    new_url = urllib.parse.urlunparse(parsed._replace(query=new_query_string))
                else:
                    # 2. Append as new query param if it was only discovered via ZAP (e.g. from form)
                    # This converts non-GET params to GET for testing which is a heuristic 
                    # but better than ignoring them.
                    new_query = copy.deepcopy(query_params)
                    new_query[param] = [payload]
                    new_query_string = urllib.parse.urlencode(new_query, doseq=True)
                    new_url = urllib.parse.urlunparse(parsed._replace(query=new_query_string))

                try:
                    resp = requests.get(new_url, headers=self.headers, timeout=5, proxies=self.proxies)
                    if payload in resp.text:
                        findings.append({
                            "vulnerability": "Reflected XSS",
                            "endpoint": url,
                            "parameter": param,
                            "payload": payload,
                            "impact": "Script injection possible via reflection",
                            "severity": "High"
                        })
                        break
                except requests.RequestException:
                    pass
        
        return findings

    def run(self, endpoints):
        all_findings = []
        for ep in endpoints:
            results = self.test_endpoint(ep)
            if results:
                all_findings.extend(results)
        return all_findings
