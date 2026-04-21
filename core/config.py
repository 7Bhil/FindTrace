import os
from dotenv import load_dotenv

load_dotenv() # Load variables from .env if it exists
from typing import Dict

# Global Timeouts
DEFAULT_TIMEOUT = 30
DNS_TIMEOUT = 10
NMAP_TIMEOUT = 60
HTTPX_TIMEOUT = 20
WHOIS_TIMEOUT = 15

# Paths
REPORTS_DIR = "reports"
SESSIONS_DIR = "sessions"

# FindTrace 2.0 - Universal Intelligence Framework
MAX_SCORE = 1000

# Region Weights
REGION_WEIGHTS = {
    "asia": 1.2,      # Frequent infrastructure abuse
    "eastern_europe": 1.5,  # High sophistication / C2
    "africa": 1.0,    # Emerging fraud patterns
    "western": 0.8,   # Well-documented threats
    "middle_east": 1.3,  # Target-rich / Specific kits
    "global": 1.0     # Baseline
}

# Global Intelligence Patterns
# Format: "Pattern": {"risk": score, "region": "region_id", "desc": "Technical finding"}
THREAT_PATTERNS = {
    # ASIA
    "ThinkPHP": {"risk": 30, "region": "asia", "desc": "ThinkPHP framework signature"},
    "Mandarin": {"risk": 20, "region": "asia", "desc": "Chinese script detected"},
    "Aliyun": {"risk": 10, "region": "asia", "desc": "Alibaba Cloud infrastructure"},
    
    # EASTERN EUROPE / RUSSIA
    "Cobalt Strike": {"risk": 80, "region": "eastern_europe", "desc": "Cobalt Strike C2 beacon"},
    "Cyrillic": {"risk": 20, "region": "eastern_europe", "desc": "Cyrillic/Russian script"},
    "Metasploit": {"risk": 80, "region": "eastern_europe", "desc": "Metasploit framework"},
    "Bitbucket-RU": {"risk": 30, "region": "eastern_europe", "desc": "Russian-language Git metadata"},
    
    # AFRICA
    "Nigerian-419": {"risk": 40, "region": "africa", "desc": "Advance Fee Fraud indicator"},
    "Crypto-Scam-NG": {"risk": 45, "region": "africa", "desc": "Social engineering / Crypto fraud"},
    
    # WESTERN / GLOBAL
    "WordPress": {"risk": 15, "region": "western", "desc": "WordPress (Check plugin vulnerabilities)"},
    "Joomla": {"risk": 15, "region": "western", "desc": "Joomla CMS detected"},
    "Phishlet": {"risk": 70, "region": "global", "desc": "AiTM Phishing proxy detected"},
    "Cryptonight": {"risk": 60, "region": "global", "desc": "Monero mining traffic detected"},
    
    # SERVICE EXPOSURES
    "3306/tcp": {"risk": 30, "region": "global", "desc": "Exposed MySQL database"},
    "27017/tcp": {"risk": 30, "region": "global", "desc": "Exposed MongoDB instance"},
    "445/tcp": {"risk": 50, "region": "global", "desc": "Exposed SMB (Lateral movement risk)"},
    "5900/tcp": {"risk": 40, "region": "global", "desc": "Exposed VNC (Remote access)"},
}

# API Keys (Loaded from .env)
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")

# Tool Binaries
BINARIES = ["dig", "nmap", "httpx", "whois", "subfinder"]

# UI Settings
BANNER = """
[bold magenta]
███████╗██╗███╗   ██╗██████╗ ████████╗██████╗  █████╗  ██████╗███████╗
██╔════╝██║████╗  ██║██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
█████╗  ██║██╔██╗ ██║██║  ██║   ██║   ██████╔╝███████║██║     █████╗  
██╔══╝  ██║██║╚██╗██║██║  ██║   ██║   ██╔══██╗██╔══██║██║     ██╔══╝  
██║     ██║██║ ╚████║██████╔╝   ██║   ██║  ██║██║  ██║╚██████╗███████╗
╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝
[/bold magenta]
[cyan]V3 Elite OSINT Platform - Hardened & Async Architecture[/cyan]
"""
