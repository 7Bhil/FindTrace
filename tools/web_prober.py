import asyncio
import asyncio.subprocess
import json
import re
from typing import Dict, Any

async def probe_web(domain: str) -> Dict[str, Any]:
    """
    Probe web using 'httpx' asynchronously.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            'httpx', '-u', domain, '-sc', '-td', '-server', '-http3', '-title', '-json', '-silent',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode().strip()
        
        if not output:
            return {"error": "No response from httpx"}
            
        data = json.loads(output)
        
        findings = {
            "url": data.get("url"),
            "status_code": data.get("status_code"),
            "title": data.get("title"),
            "server": data.get("server"),
            "tech": data.get("tech", []),
            "http3": data.get("http3", False),
            "threats": []
        }
        
        techs = [t.lower() for t in findings["tech"]]
        if "thinkphp" in techs:
            findings["threats"].append("ThinkPHP framework detected")
            
        if findings["http3"]:
            findings["threats"].append("HTTP/3 supported")
            
        title_text = str(findings.get("title", ""))
        if title_text and re.search(r'[\u4e00-\u9fff]', title_text):
            findings["threats"].append("Mandarin characters detected in page title")
            
        return findings
    except Exception as e:
        return {"error": f"Web probe async error: {str(e)}"}

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        asyncio.run(probe_web(sys.argv[1]))
