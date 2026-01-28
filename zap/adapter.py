def zap_surface_to_endpoints(attack_surface, base_url):
    """
    Convert ZAP attack surface output into endpoints usable by IDORTester
    """

    endpoints = []

    for item in attack_surface:
        path = item.get("path")
        params = item.get("parameters", [])

        if not path or not params:
            continue

        # Build query string with dummy values
        query = "&".join([f"{p}=1" for p in params])
        
        if path.startswith("http"):
            full_url = f"{path}?{query}"
        else:
            full_url = f"{base_url}{path}?{query}"

        endpoints.append({
            "url": full_url,
            "method": item.get("method", "GET"),
        })

    return endpoints
