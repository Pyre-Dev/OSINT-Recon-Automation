import requests

def check_abuseip(ip, api_key):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90"
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()["data"]
            return {
                "ip": data["ipAddress"],
                "abuse_score": data["abuseConfidenceScore"],
                "total_reports": data["totalReports"],
                "last_reported": data.get("lastReportedAt", "N/A"),
                "country": data.get("countryCode", "N/A")
            }
        else:
            return {"error": f"AbuseIPDB lookup failed: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}