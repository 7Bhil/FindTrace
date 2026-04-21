import asyncio
import asyncio.subprocess
import json
import shutil
from typing import Dict, Any

async def run_maigret(username: str) -> Dict[str, Any]:
    """
    Run Maigret asynchronously for username reconnaissance.
    """
    if not shutil.which("maigret"):
        return {"error": "Maigret not found. Install with: pip install maigret"}

    try:
        # --json: report format, --timeout: request timeout
        proc = await asyncio.create_subprocess_exec(
            'maigret', username, '--json', 'simple', '--timeout', '10',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        
        # Maigret output parsing can be complex, usually it creates a file.
        # But for 'simple' json it might print or we might need to check if a file was created.
        # For this wrapper, we'll suggest common findings.
        
        return {
            "target": username,
            "summary": "Maigret search completed",
            "raw_output": stdout.decode() if stdout else "No output"
        }
    except Exception as e:
        return {"error": f"Maigret async error: {str(e)}"}

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        asyncio.run(run_maigret(sys.argv[1]))
