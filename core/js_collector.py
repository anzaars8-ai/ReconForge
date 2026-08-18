import asyncio
import aiohttp
import re
from typing import Set, List, Dict
from urllib.parse import urljoin

class JSCollector:
    def __init__(self):
        self.js_files = set()
        self.extracted_urls = set()

    async def _fetch(self, session: aiohttp.ClientSession, url: str) -> str:
        try:
            async with session.get(url, timeout=10, ssl=False) as resp:
                return await resp.text()
        except: return ""

    async def collect(self, base_url: str, session: aiohttp.ClientSession) -> Dict:
        result = {"js_files": [], "urls": [], "endpoints": [], "secrets": []}
        html = await self._fetch(session, base_url)
        if not html: return result
        src_pattern = re.compile(r'<script[^>]*src=["\u2019]([^"\u2019]+)["\u2019]', re.IGNORECASE)
        for match in src_pattern.finditer(html):
            js_url = urljoin(base_url, match.group(1))
            result["js_files"].append(js_url)
            js_content = await self._fetch(session, js_url)
            if js_content:
                url_pattern = re.compile(r'(https?://[^\s"\'<>]+)')
                for u in url_pattern.findall(js_content):
                    result["urls"].append(u)
                ep_pattern = re.compile(r'["\u2019](/[a-zA-Z0-9_\-./?&=#]+)["\u2019]')
                for ep in ep_pattern.findall(js_content):
                    if any(x in ep.lower() for x in ['api', 'v1', 'v2', 'graphql', 'rest']):
                        result["endpoints"].append(ep)
                secrets = []
                for pat, label in [(r'(?:api[_-]?key|api_key|apikey)\s*[=:]\s*["\u2019]([^"\u2019]+)["\u2019]', "API Key"), (r'(?:secret|secret_key|secretkey)\s*[=:]\s*["\u2019]([^"\u2019]+)["\u2019]', "Secret"), (r'(?:token|access_token|bearer)\s*[=:]\s*["\u2019]([^"\u2019]+)["\u2019]', "Token"), (r'(?:password|passwd)\s*[=:]\s*["\u2019]([^"\u2019]+)["\u2019]', "Password")]:
                    for m in re.findall(pat, js_content, re.IGNORECASE):
                        val = m if isinstance(m, str) else m[0]
                        if len(val) > 4: secrets.append({"type": label, "value": val[:100]})
                result["secrets"].extend(secrets)
        result["urls"] = list(set(result["urls"]))
        result["endpoints"] = list(set(result["endpoints"]))
        return result
