import asyncio
import aiohttp
from typing import List, Dict, Set, Optional
from urllib.parse import urljoin

class DirectoryDiscoverer:
    def __init__(self, threads: int = 50, extensions: List[str] = None):
        self.threads = threads
        self.extensions = extensions or [".php", ".asp", ".aspx", ".jsp", ".do", ".action", ""]
        self.semaphore = asyncio.Semaphore(threads)
        self.results: Dict[str, Dict] = {}

    async def _check_path(self, session: aiohttp.ClientSession, base_url: str, path: str) -> Optional[Dict]:
        async with self.semaphore:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            try:
                async with session.get(url, timeout=5, ssl=False, allow_redirects=False) as resp:
                    if resp.status in [200, 201, 204, 301, 302, 303, 307, 308, 401, 403, 500]:
                        return {"url": url, "status": resp.status, "content_length": resp.headers.get("Content-Length", "N/A"), "redirect": resp.headers.get("Location", "")}
            except: pass
        return None

    def load_wordlist(self, path: str) -> List[str]:
        try:
            with open(path, "r", errors="ignore") as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            return ["admin", "login", "wp-admin", "administrator", "dashboard", "api", "v1", "v2", "graphql", "swagger", "docs", ".git", ".env", "config", "backup", "dump", "uploads", "files", "download", "assets", "static", "robots.txt", "sitemap.xml", "crossdomain.xml", "phpinfo.php", "info.php", "test.php"]

    async def discover(self, base_url: str, wordlist_path: str) -> Dict[str, Dict]:
        paths = self.load_wordlist(wordlist_path)
        connector = aiohttp.TCPConnector(limit=self.threads, limit_per_host=10)
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
            tasks = [self._check_path(session, base_url, path) for path in paths]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, dict):
                    self.results[result["url"]] = result
        return self.results
