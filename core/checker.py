import shutil
from typing import List, Dict

def check_dependencies(dependencies: List[str]) -> Dict[str, bool]:
    """
    Check if the required system binaries are available in the PATH.
    """
    status = {}
    for dep in dependencies:
        status[dep] = shutil.which(dep) is not None
    return status

def get_missing_dependencies(dependencies: List[str]) -> List[str]:
    """
    Return a list of missing dependencies.
    """
    status = check_dependencies(dependencies)
    return [dep for dep, available in status.items() if not available]
