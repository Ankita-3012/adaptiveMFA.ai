import requests

def get_location_from_ip(ip: str):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json",
                                timeout=3)
        if response.status_code == 200:
            data = response.json()
            loc = data.get("loc", "0,0").split(",")
            return {
                "city": data.get("city"),
                "region": data.get("region"),
                "country": data.get("country"),
                "latitude": float(loc[0]),
                "longitude": float(loc[1]),
            }
        else:
            return {}
    except:
        return {}
