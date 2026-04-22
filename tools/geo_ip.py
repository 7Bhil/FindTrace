import aiohttp
import asyncio
import sys
from typing import Dict, Any

async def get_ip_geo(ip: str, session: aiohttp.ClientSession = None) -> Dict[str, Any]:
    """
    Get geographic information for an IP address asynchronously.
    """
    if not ip or ":" in ip:
        return {}

    url = f"http://ip-api.com/json/{ip}"
    
    # Internal logic to handle the request
    async def fetch(s: aiohttp.ClientSession):
        try:
            async with s.get(url, timeout=5) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get("status") == "success":
                        return {
                            "country": data.get("country"),
                            "countryCode": data.get("countryCode"),
                            "city": data.get("city"),
                            "isp": data.get("isp"),
                            "org": data.get("org"),
                            "hostname": data.get("as", "N/A")
                        }
        except Exception:
            pass
        return {}

    if session:
        return await fetch(session)
    
    async with aiohttp.ClientSession() as new_session:
        return await fetch(new_session)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        print(asyncio.run(get_ip_geo(sys.argv[1])))
