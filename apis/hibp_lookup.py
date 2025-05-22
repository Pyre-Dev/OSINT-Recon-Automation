import requests

def check_hibp(email, api_key):
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {
        "hibp-api-key": api_key,
        "user-agent": "OSINT-Toolkit"
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            breaches = response.json()
            return {
                "email": email,
                "breaches_found": len(breaches),
                "breach_names": [b["Name"] for b in breaches]
            }
        elif response.status_code == 404:
            return {"email": email, "breaches_found": 0}
        else:
            return {"error": f"HIBP lookup failed: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}