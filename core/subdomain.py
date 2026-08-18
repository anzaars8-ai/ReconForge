import asyncio
import aiohttp
import dns.resolver
from typing import Set, List
from urllib.parse import urlparse

class SubdomainEnumerator:
    def __init__(self, domain: str, threads: int = 50):
        self.domain = domain
        self.threads = threads
        self.subdomains: Set[str] = set()
        self.session = None

    async def _fetch_crtsh(self) -> Set[str]:
        results = set()
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        try:
            async with self.session.get(url, timeout=15) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data:
                        name = entry.get("name_value", "")
                        for sub in name.split("\\n"):
                            if sub.endswith(f".{self.domain}") and "*" not in sub:
                                results.add(sub.lower())
        except: pass
        return results

    async def _fetch_hackertarget(self) -> Set[str]:
        results = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        try:
            async with self.session.get(url, timeout=15) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    for line in text.split("\\n"):
                        parts = line.split(",")
                        if len(parts) >= 1:
                            results.add(parts[0].lower().strip())
        except: pass
        return results

    async def _fetch_alienvault(self) -> Set[str]:
        results = set()
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        try:
            async with self.session.get(url, timeout=15) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data.get("passive_dns", []):
                        hostname = entry.get("hostname", "")
                        if hostname.endswith(f".{self.domain}"):
                            results.add(hostname.lower())
        except: pass
        return results

    async def _fetch_wayback(self) -> Set[str]:
        results = set()
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}&output=json&fl=original&collapse=urlkey"
        try:
            async with self.session.get(url, timeout=15) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data[1:]:
                        original = entry[0] if isinstance(entry, list) else entry
                        parsed = urlparse(original)
                        hostname = parsed.hostname or ""
                        if hostname.endswith(f".{self.domain}"):
                            results.add(hostname.lower())
        except: pass
        return results

    async def _fetch_dnsdumpster(self) -> Set[str]:
        results = set()
        url = "https://dnsdumpster.com/"
        try:
            async with self.session.get(url, timeout=15) as resp:
                text = await resp.text()
                import re
                csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', text)
                if csrf_match:
                    csrf = csrf_match.group(1)
                    headers = {"Referer": url}
                    data = {"csrfmiddlewaretoken": csrf, "targetip": self.domain, "user": "free"}
                    async with self.session.post(url, data=data, headers=headers, timeout=15) as resp2:
                        if resp2.status == 200:
                            html = await resp2.text()
                            for match in re.finditer(r'<td[^>]*>([^<]+\\.' + re.escape(self.domain) + r')</td>', html):
                                results.add(match.group(1).lower().strip())
        except: pass
        return results

    async def enumerate_all(self) -> Set[str]:
        connector = aiohttp.TCPConnector(limit=self.threads, limit_per_host=10)
        async with aiohttp.ClientSession(connector=connector) as session:
            self.session = session
            tasks = [self._fetch_crtsh(), self._fetch_hackertarget(), self._fetch_alienvault(), self._fetch_wayback(), self._fetch_dnsdumpster()]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result_set in results:
                if isinstance(result_set, set):
                    self.subdomains.update(result_set)
        self.subdomains.discard(self.domain)
        return self.subdomains

    def save_results(self, path: str):
        with open(path, "w") as f:
            for sub in sorted(self.subdomains):
                f.write(f"{sub}\\n")
        print(f"[+] Saved {len(self.subdomains)} subdomains to {path}")
