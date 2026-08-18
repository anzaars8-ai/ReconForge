import asyncio
import aiohttp
import dns.resolver
import re
from typing import List, Dict, Optional

TAKEOVER_SIGNATURES = {
    "aws_s3": {"cname": [r"\\.s3\\.amazonaws\\.com$", r"\\.s3-website[-\\w]+\\.amazonaws\\.com$"], "response": ["NoSuchBucket", "The specified bucket does not exist"]},
    "cloudfront": {"cname": [r"\\.cloudfront\\.net$"], "response": ["ERROR: The request could not be satisfied"]},
    "heroku": {"cname": [r"\\.herokuapp\\.com$"], "response": ["There's nothing here, yet", "Heroku | No such app"]},
    "github_pages": {"cname": [r"\\.github\\.io$"], "response": ["404: There isn't a GitHub Pages site here"]},
    "azure_trafficmanager": {"cname": [r"\\.trafficmanager\\.net$"], "response": ["The web page you are looking for does not exist"]},
    "azure_cloudapp": {"cname": [r"\\.cloudapp\\.net$", r"\\.azurewebsites\\.net$"], "response": ["The web page you are looking for does not exist"]},
    "shopify": {"cname": [r"\\.myshopify\\.com$"], "response": ["Sorry, this shop is currently unavailable"]},
    "bitbucket": {"cname": [r"\\.bitbucket\\.io$"], "response": ["Repository not found"]},
    "surge": {"cname": [r"\\.surge\\.sh$"], "response": ["project not found"]},
}

class SubdomainTakeoverDetector:
    def __init__(self, domain: str):
        self.domain = domain

    async def _check_cname(self, subdomain: str) -> Optional[str]:
        try:
            answers = dns.resolver.resolve(subdomain, 'CNAME', lifetime=10)
            return str(answers[0].target).rstrip(".")
        except: return None

    async def check_subdomain(self, session: aiohttp.ClientSession, subdomain: str) -> Optional[Dict]:
        cname = await self._check_cname(subdomain)
        if not cname: return None
        cname_lower = cname.lower()
        for service, sig in TAKEOVER_SIGNATURES.items():
            if any(re.search(p, cname_lower) for p in sig["cname"]):
                try:
                    async with session.get(f"http://{subdomain}", timeout=10, ssl=False) as resp:
                        text = await resp.text()
                except:
                    try:
                        async with session.get(f"https://{subdomain}", timeout=10, ssl=False) as resp:
                            text = await resp.text()
                    except: text = ""
                if any(fp.lower() in text.lower() for fp in sig["response"]):
                    return {"subdomain": subdomain, "cname": cname, "service": service, "vulnerable": True, "confidence": "high"}
        return None

    async def scan(self, subdomains: List[str]) -> List[Dict]:
        vulnerable = []
        connector = aiohttp.TCPConnector(limit=20)
        async with aiohttp.ClientSession(connector=connector) as session:
            results = await asyncio.gather(*[self.check_subdomain(session, sub) for sub in subdomains], return_exceptions=True)
            for r in results:
                if isinstance(r, dict) and r.get("vulnerable"):
                    vulnerable.append(r)
        return vulnerable
