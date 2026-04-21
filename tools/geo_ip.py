import aiohttp
import asyncio
from typing import Dict, Any

async def get_ip_geo(ip: str) -> Dict[str, Any]:
    """
    Get geographic information for an IP address asynchronously.
    Uses ip-api.com (Free API).
    """
    # Simple validation
    if not ip or ":" in ip: # Skip IPv6 for now or handle separately
        return {}

    url = f"http://ip-api.com/json/{ip}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=5) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get("status") == "success":
                        return {
                            "country": data.get("country"),
                            "countryCode": data.get("countryCode"),
                            "city": data.get("city"),
                            "isp": data.get("isp"),
                            "org": data.get("org")
                        }
    except Exception:
        pass # Silently fail for enrichment
    return {}

if __name__ == "__main__":
    if len(asyncio.sys.argv) > 1:
        print(asyncio.run(get_ip_geo(asyncio.sys.argv[1])))
