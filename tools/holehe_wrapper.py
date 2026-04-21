import asyncio
import asyncio.subprocess
import shutil
from typing import Dict, Any

async def run_holehe(email: str) -> Dict[str, Any]:
    """
    Run Holehe asynchronously for email presence detection.
    """
    if not shutil.which("holehe"):
        return {"error": "Holehe not found. Install with: pip install holehe"}

    try:
        proc = await asyncio.create_subprocess_exec(
            'holehe', email, '--only-used',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode()
        
        # Holehe uses rich/color in stdout, we'll take the raw text
        return {
            "target": email,
            "used_sites": [line.strip() for line in output.split('\n') if line and "[+]" in line],
            "raw": output
        }
    except Exception as e:
        return {"error": f"Holehe async error: {str(e)}"}

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        asyncio.run(run_holehe(sys.argv[1]))
