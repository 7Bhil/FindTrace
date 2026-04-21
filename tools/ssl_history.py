import asyncio
import aiohttp
import json
from typing import Dict, Any

async def get_ssl_history(domain: str) -> Dict[str, Any]:
    """
    Get SSL certificate history using crt.sh API asynchronously.
    """
    url = f"https://crt.sh/?q={domain}&output=json"
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=15) as response:
                if response.status != 200:
                    return {"error": f"crt.sh returned status {response.status}"}
                
                data = await response.json()
                
                # Limit to 50 most recent certificates
                limited_data = data[:50]
                
                return {
                    "certificates_count": len(data),
                    "recent_certificates": limited_data,
                    "checked_at": "crt.sh"
                }
    except asyncio.TimeoutError:
        return {"error": "SSL history request timed out"}
    except Exception as e:
        return {"error": f"SSL history async error: {str(e)}"}
    
    return {"error": "Unexpected end of function"}

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        asyncio.run(get_ssl_history(sys.argv[1]))
