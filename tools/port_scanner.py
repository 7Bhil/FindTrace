import asyncio
import asyncio.subprocess
import json
from typing import List, Dict, Any

async def scan_ports(ip_or_domain: str) -> Dict[str, Any]:
    """
    Scan ports asynchronously using 'nmap'.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            'nmap', '-p', '22,80,443', '-sV', '-Pn', '--open', ip_or_domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode()
        
        open_ports = []
        lines = output.split('\n')
        for line in lines:
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    version = " ".join(parts[3:]) if len(parts) > 3 else "Unknown"
                    open_ports.append({
                        "port": parts[0],
                        "state": parts[1],
                        "service": parts[2],
                        "version": version
                    })
        
        heuristics = []
        if "Ubuntu" in output:
            heuristics.append("OS identified as Ubuntu Linux.")
        if "google" in output.lower():
            heuristics.append("Infrastructure suggests Google Cloud.")
            
        return {
            "target": ip_or_domain,
            "open_ports": open_ports,
            "heuristics": heuristics
        }
    except Exception as e:
        return {"error": f"Nmap async error: {str(e)}"}

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        asyncio.run(scan_ports(sys.argv[1]))
