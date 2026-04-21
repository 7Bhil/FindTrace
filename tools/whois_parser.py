import asyncio
import asyncio.subprocess
import json
import re
from typing import Dict, Any

async def get_whois_info(domain_or_ip: str) -> Dict[str, Any]:
    """
    Get WHOIS information asynchronously.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            'whois', domain_or_ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode()
        
        info = {
            "registrant_country": "",
            "registrar": "",
            "creation_date": "",
            "org": ""
        }
        
        patterns = {
            "registrant_country": r"(?i)Registrant Country:\s*(.*)",
            "registrar": r"(?i)Registrar:\s*(.*)",
            "creation_date": r"(?i)Creation Date:\s*(.*)",
            "org": r"(?i)Registrant Organization:\s*(.*)"
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, output)
            if match:
                info[key] = match.group(1).strip()
                
        if not info["registrant_country"]:
            country_match = re.search(r"(?i)country:\s*(.*)", output)
            if country_match:
                info["registrant_country"] = country_match.group(1).strip()

        raw_output = str(output)
        return {
            "target": domain_or_ip,
            "info": info,
            "raw": raw_output if len(raw_output) < 2000 else raw_output[:2000] + "... [truncated]"
        }
    except Exception as e:
        return {"error": f"WHOIS async error: {str(e)}"}

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        asyncio.run(get_whois_info(sys.argv[1]))
