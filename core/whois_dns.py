import asyncio
import dns.resolver
import whois
from typing import Dict

class WhoisDNSAnalyzer:
    def __init__(self, domain: str):
        self.domain = domain

    async def get_whois(self) -> Dict:
        loop = asyncio.get_event_loop()
        try:
            w = await loop.run_in_executor(None, whois.whois, self.domain)
            return {"registrar": w.registrar or "N/A", "registrant": w.name or "N/A", "organization": w.org or "N/A", "country": w.country or "N/A", "creation_date": str(w.creation_date) if w.creation_date else "N/A", "expiration_date": str(w.expiration_date) if w.expiration_date else "N/A", "name_servers": w.name_servers or [], "emails": w.emails or []}
        except Exception as e:
            return {"error": str(e)}

    async def get_dns_records(self) -> Dict:
        records = {}
        for rtype in ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'SRV', 'CAA']:
            try:
                answers = dns.resolver.resolve(self.domain, rtype, lifetime=10)
                records[rtype] = [str(r) for r in answers]
            except: records[rtype] = []
        return records

    async def analyze(self) -> Dict:
        whois_info, dns_records = await asyncio.gather(self.get_whois(), self.get_dns_records())
        return {"domain": self.domain, "whois": whois_info, "dns_records": dns_records}
