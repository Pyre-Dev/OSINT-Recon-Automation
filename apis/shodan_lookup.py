import requests

def search_shodan(ip, api_key):
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return {
                "ip": data.get("ip_str"),
                "organization": data.get("org"),
                "hostnames": data.get("hostnames"),
                "ports": data.get("ports"),
                "location": data.get("location", {}).get("country_name")
            }
        else:
            return {"error": f"Shodan lookup failed: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}