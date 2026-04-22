import asyncio
import asyncio.subprocess
import json
from typing import Dict, List

async def get_dns_records(domain: str) -> Dict[str, List[str]]:
    """
    Get A, MX, NS, and TXT records for a domain using 'dig' asynchronously.
    """
    records = {}
    types = ['A', 'MX', 'NS', 'TXT']
    
    for t in types:
        try:
            # -t: type, +short: only answer
            proc = await asyncio.create_subprocess_exec(
                'dig', t, domain, '+short', '-4', # Force IPv4 for simplicity
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            # Add a timeout to prevent hanging
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                output = stdout.decode().strip()
                if output:
                    records[t] = [line.strip('" ') for line in output.split('\n') if line]
                else:
                    records[t] = []
            except asyncio.TimeoutError:
                if proc.returncode is None:
                    proc.kill()
                records[t] = []
        except Exception:
            records[t] = []
            
    return records

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        asyncio.run(get_dns_records(sys.argv[1]))
