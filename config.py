import os
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class Config:
    targets: List[str] = field(default_factory=list)
    threads: int = 50
    output_dir: str = "./results"
    wordlist: str = "./wordlists/directory.txt"
    subdomain_list: Optional[str] = None
    depth: str = "full"
    
    # ============ ALL TOOLS ============
    # Subdomain Enumeration
    use_subfinder: bool = True
    use_amass: bool = False  # Slow, enable with --full
    use_assetfinder: bool = True
    
    # URL & Endpoint Discovery
    use_gau: bool = True
    use_katana: bool = True
    use_waybackurls: bool = True
    
    # Port & Service Discovery
    use_naabu: bool = True
    use_nmap: bool = True
    
    # HTTP Probing
    use_httpx: bool = True
    
    # Web Vulnerability Scanners
    use_nuclei: bool = True
    use_zap: bool = False    # OWASP ZAP - slow, enable with --full
    use_nikto: bool = False  # Enable with --full
    
    # SQL Injection
    use_sqlmap: bool = False  # Enable with --sql
    
    # Content Discovery & Fuzzing
    use_ffuf: bool = True
    use_dirsearch: bool = True
    use_gobuster: bool = True
    
    # Parameter & Endpoint Discovery
    use_arjun: bool = True
    use_linkfinder: bool = True
    
    # Cloud & Configuration Review
    use_trufflehog: bool = True
    use_gitleaks: bool = True
    
    # ============ TELEGRAM ============
    telegram_bot_token: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
    telegram_chat_id: str = os.getenv("TELEGRAM_CHAT_ID", "")
    telegram_notify_high_only: bool = False  # Send all findings or only high
    
    # ============ API KEYS ============
    shodan_api: str = os.getenv("SHODAN_API", "")
    virustotal_api: str = os.getenv("VIRUSTOTAL_API", "")
    github_token: str = os.getenv("GITHUB_TOKEN", "")
    
    # Ports (for built-in scanner fallback)
    ports: List[int] = field(default_factory=lambda: [21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000, 27017])
