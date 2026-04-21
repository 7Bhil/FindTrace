import asyncio
import asyncio.subprocess
import json
import shutil
from typing import Dict, Any

async def discover_subdomains(domain: str) -> Dict[str, Any]:
    """
    Discover subdomains asynchronously using 'subfinder'.
    """
    if not shutil.which("subfinder"):
        return {"error": "subfinder not found"}

    try:
        proc = await asyncio.create_subprocess_exec(
            'subfinder', '-d', domain, '-silent', '-json',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        
        subdomains = []
        for line in stdout.decode().strip().split('\n'):
            if line:
                try:
                    data = json.loads(line)
                    subdomains.append(data.get("host"))
                except json.JSONDecodeError:
                    subdomains.append(line)
                    
        return {
            "domain": domain,
            "subdomains": list(set(subdomains)),
            "count": len(subdomains)
        }
    except Exception as e:
        return {"error": f"Subfinder async error: {str(e)}"}

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        asyncio.run(discover_subdomains(sys.argv[1]))
