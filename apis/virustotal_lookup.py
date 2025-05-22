import requests

def check_virustotal(target, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()["data"]["attributes"]
            return {
                "reputation": data["reputation"],
                "last_analysis_stats": data["last_analysis_stats"],
                "network": data.get("network", "N/A"),
                "asn": data.get("asn", "N/A")
            }
        else:
            return {"error": f"VirusTotal lookup failed: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}