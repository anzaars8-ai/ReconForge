import asyncio
import aiohttp
from typing import Dict, List, Optional, Tuple

class LiveHostDetector:
    def __init__(self, threads: int = 50, timeout: int = 5):
        self.threads = threads
        self.timeout = timeout
        self.alive_hosts: Dict[str, Dict] = {}

    async def _check_https(self, session: aiohttp.ClientSession, host: str) -> Optional[Tuple[str, int, str]]:
        try:
            url = f"https://{host}"
            async with session.get(url, timeout=self.timeout, ssl=False, allow_redirects=True) as resp:
                return (host, resp.status, url)
        except: return None

    async def _check_http(self, session: aiohttp.ClientSession, host: str) -> Optional[Tuple[str, int, str]]:
        try:
            url = f"http://{host}"
            async with session.get(url, timeout=self.timeout, allow_redirects=True) as resp:
                return (host, resp.status, url)
        except: return None

    async def check_all(self, hosts: List[str]) -> Dict[str, Dict]:
        connector = aiohttp.TCPConnector(limit=self.threads, limit_per_host=5)
        timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout_obj) as session:
            tasks = [self._check_https(session, host) for host in hosts]
            if len(hosts) <= 100:
                tasks += [self._check_http(session, host) for host in hosts]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, tuple) and result[0]:
                    host, status, url = result
                    if host not in self.alive_hosts:
                        self.alive_hosts[host] = {"status_codes": {}, "urls": []}
                    self.alive_hosts[host]["status_codes"][url] = status
                    self.alive_hosts[host]["urls"].append(url)
        return self.alive_hosts
