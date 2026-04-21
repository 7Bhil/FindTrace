import re

def is_valid_domain(domain: str) -> bool:
    """
    Validate domain name format to prevent command injection and ensure data quality.
    """
    if not domain:
        return False
    # Strict alphanumeric + hyphens + dots
    pattern = r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"
    return bool(re.match(pattern, domain.lower()))

def detect_target_type(target: str) -> str:
    """
    Auto-detect the type of target: 'domain', 'ip', 'email', 'phone', 'hash' or 'username'.
    FindTrace 2.0 Global Standard.
    """
    target = target.lower().strip()
    
    # IPv4 / IPv6 (Basic)
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target) or ":" in target:
        return "ip"
    
    # Email
    if re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", target):
        return "email"
    
    # Phone Number (+XXXXX...)
    if re.match(r"^\+?[0-9]{7,15}$", target):
        return "phone"
    
    # Hashes (MD5, SHA1, SHA256)
    if re.match(r"^[a-fA-F0-9]{32,64}$", target):
        return "hash"
    
    # Domain
    if is_valid_domain(target):
        return "domain"
    
    # Default to username/company
    return "username"

def sanitize_filename(name: str) -> str:
    """
    Sanitize a string to be safe for use as a filename (prevents path traversal).
    """
    # Remove everything except alphanumeric, dots, and hyphens
    return re.sub(r'[^a-zA-Z0-9.-]', '_', name)
