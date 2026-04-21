import aiohttp
from core.config import SHODAN_API_KEY
from typing import Dict, Any

async def scan_shodan(ip: str) -> Dict[str, Any]:
    """
    Query Shodan for IP intelligence using API key.
    """
    if not SHODAN_API_KEY:
        return {"error": "SHODAN_API_KEY not set in .env"}

    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 401:
                    return {"error": "Invalid Shodan API Key"}
                else:
                    return {"error": f"Shodan API error: {response.status}"}
    except Exception as e:
        return {"error": f"Shodan connection error: {str(e)}"}
