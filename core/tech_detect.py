import asyncio
import aiohttp
import re
from typing import Dict, List, Optional, Set

class TechDetector:
    def __init__(self):
        self.technologies = {
            "WordPress": {"headers": {"x-powered-by": None}, "body": [r'/wp-content/', r'/wp-admin/', r'/wp-includes/', r'wp-json'], "cookies": ["wordpress_", "wp-settings-"]},
            "React": {"headers": None, "body": [r'_react', r'__NEXT_DATA__', r'reactRoot', r'data-react'], "cookies": None},
            "Angular": {"headers": None, "body": [r'ng-app', r'ng-version', r'angular'], "cookies": None},
            "Vue.js": {"headers": None, "body": [r'vue.', r'__VUE__', r'v-bind', r'v-model'], "cookies": None},
            "Apache": {"headers": {"server": r"Apache(?:/(\\d+\\.\\d+\\.\\d+))?"}, "body": None, "cookies": None},
            "Nginx": {"headers": {"server": r"nginx(?:/(\\d+\\.\\d+\\.\\d+))?"}, "body": None, "cookies": None},
            "Cloudflare": {"headers": {"server": r"cloudflare", "cf-ray": None}, "body": [r"__cf_bm", r"cf_bm"], "cookies": ["__cfduid"]},
            "PHP": {"headers": {"x-powered-by": r"PHP(?:/(\\d+\\.\\d+\\.\\d+))?"}, "body": [r'\\.php'], "cookies": ["PHPSESSID"]},
            "Node.js": {"headers": {"x-powered-by": r"Express", "server": r"Node"}, "body": None, "cookies": None},
            "Joomla": {"headers": None, "body": [r'/components/', r'/modules/', r'/templates/', r'joomla'], "cookies": None},
            "Drupal": {"headers": {"x-drupal": None, "x-generator": r"Drupal"}, "body": [r'drupal', r'/sites/default/'], "cookies": None},
            "Laravel": {"headers": {"x-powered-by": None}, "body": [r'laravel', r'csrf-token'], "cookies": ["laravel_session"]},
            "ASP.NET": {"headers": {"x-aspnet-version": None, "x-powered-by": r"ASP\\.NET"}, "body": [r'__VIEWSTATE', r'__EVENTVALIDATION'], "cookies": [".ASPXAUTH"]},
        }

    async def detect(self, url: str, html: str, headers: Dict) -> Dict[str, Dict]:
        detected = {}
        for tech_name, signatures in self.technologies.items():
            versions = set()
            evidence = []
            if signatures["headers"]:
                for header, pattern in signatures["headers"].items():
                    for key, value in headers.items():
                        if key.lower() == header.lower():
                            evidence.append(f"Header: {key}={value}")
                            if pattern:
                                match = re.search(pattern, value)
                                if match and match.group(1):
                                    versions.add(match.group(1))
            if signatures["body"] and html:
                for pattern in signatures["body"]:
                    matches = re.findall(pattern, html, re.IGNORECASE)
                    if matches:
                        evidence.append(f"Body pattern: {pattern}")
            if signatures["cookies"]:
                set_cookie = headers.get("Set-Cookie", "") or ""
                for cookie in signatures["cookies"]:
                    if cookie in set_cookie:
                        evidence.append(f"Cookie: {cookie}")
            if evidence:
                detected[tech_name] = {"version": list(versions)[0] if versions else "Unknown", "confidence": min(len(evidence) * 25, 100), "evidence": evidence}
        return detected
