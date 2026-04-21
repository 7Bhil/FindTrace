import aiohttp
from core.config import VIRUSTOTAL_API_KEY
from typing import Dict, Any

async def scan_virustotal(target: str) -> Dict[str, Any]:
    """
    Query VirusTotal for domain/IP intelligence.
    """
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not set"}

    # Use the domain/ip report endpoint
    url = f"https://www.virustotal.com/api/v3/domains/{target}"
    if any(c.isdigit() for c in target) and "." in target: # Simple IP guess
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    attr = data.get("data", {}).get("attributes", {})
                    return {
                        "reputation": attr.get("reputation", 0),
                        "last_analysis_stats": attr.get("last_analysis_stats", {}),
                        "categories": attr.get("categories", {})
                    }
                elif response.status == 404:
                    return {"info": "Target not found in VirusTotal database"}
                else:
                    return {"error": f"VirusTotal API error: {response.status}"}
    except Exception as e:
        return {"error": f"VT connection error: {str(e)}"}
