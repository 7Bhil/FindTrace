import aiohttp
from core.config import ABUSEIPDB_API_KEY
from typing import Dict, Any

async def check_abuseip(ip: str) -> Dict[str, Any]:
    """
    Check IP reputation on AbuseIPDB.
    """
    if not ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY not set"}

    url = "https://api.abuseipdb.com/api/v2/check"
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90"
    }
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, params=params, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("data", {})
                else:
                    return {"error": f"AbuseIPDB API error: {response.status}"}
    except Exception as e:
        return {"error": f"AbuseIPDB connection error: {str(e)}"}
