import asyncio
import socket
from typing import Dict, List, Optional
from dataclasses import dataclass

SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    2049: "NFS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9000: "HTTP-Alt2", 27017: "MongoDB"
}

@dataclass
class PortResult:
    port: int
    state: str
    service: str
    banner: Optional[str] = None

class PortScanner:
    def __init__(self, threads: int = 100, timeout: int = 2):
        self.threads = threads
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(threads)

    async def _scan_port(self, host: str, port: int) -> Optional[PortResult]:
        async with self.semaphore:
            try:
                loop = asyncio.get_event_loop()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = await loop.run_in_executor(None, sock.connect_ex, (host, port))
                sock.close()
                if result == 0:
                    service = SERVICE_MAP.get(port, "Unknown")
                    return PortResult(port=port, state="open", service=service)
            except: pass
        return None

    async def scan(self, host: str, ports: List[int]) -> List[PortResult]:
        tasks = [self._scan_port(host, port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        open_ports = [r for r in results if isinstance(r, PortResult)]
        return sorted(open_ports, key=lambda x: x.port)
