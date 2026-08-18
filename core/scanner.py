import asyncio
import os
import sys
import json
import aiohttp
from datetime import datetime
from typing import Dict, List, Set, Optional
from pathlib import Path

from config import Config
from core.subdomain import SubdomainEnumerator
from core.livehost import LiveHostDetector
from core.ports import PortScanner
from core.tech_detect import TechDetector
from core.directory import DirectoryDiscoverer
from core.whois_dns import WhoisDNSAnalyzer
from core.ssl import SSLAnalyzer
from core.takeover import SubdomainTakeoverDetector
from core.js_collector import JSCollector
from core.tool_runner import ToolRunner
from reporting.generator import ReportGenerator
from utils.notifier import TelegramNotifier

class ReconScanner:
    def __init__(self, config: Config):
        self.config = config
        self.start_time = datetime.now()
        self.all_results = {}
        self.notifier = TelegramNotifier(config.telegram_bot_token, config.telegram_chat_id)
        self.tools_used = set()
        
    async def scan_target(self, target: str) -> Dict:
        """Run full recon on a single target using ALL integrated tools"""
        print(f"\n{'='*60}")
        print(f"  Scanning: {target}")
        print(f"{'='*60}")
        
        results = {
            "target": target,
            "start_time": datetime.now().isoformat(),
            "subdomains": [],
            "urls": [],
            "alive_hosts": {},
            "open_ports": {},
            "technologies": {},
            "directories": {},
            "whois_dns": {},
            "ssl_info": {},
            "takeovers": [],
            "nuclei_vulns": [],
            "nikto_findings": [],
            "zap_findings": [],
            "sqlmap_findings": [],
            "ffuf_findings": [],
            "dirsearch_findings": [],
            "gobuster_findings": [],
            "js_analysis": [],
            "secrets_found": [],
            "tools_used": [],
        }
        
        target_dir = os.path.join(self.config.output_dir, target)
        os.makedirs(target_dir, exist_ok=True)
        
        # ============ PHASE 1: SUBDOMAIN ENUMERATION ============
        print("\n[Phase 1] Subdomain Enumeration (subfinder, assetfinder, amass)")
        all_subdomains = set()
        
        if self.config.subdomain_list:
            with open(self.config.subdomain_list) as f:
                for line in f:
                    if line.strip():
                        all_subdomains.add(line.strip().lower())
            results["tools_used"].append("custom-list")
        
        enum_tasks = []
        if self.config.use_subfinder:
            enum_tasks.append(ToolRunner.subfinder(target))
            self.tools_used.add("subfinder")
        if self.config.use_amass:
            enum_tasks.append(ToolRunner.amass(target))
            self.tools_used.add("amass")
        if self.config.use_assetfinder:
            enum_tasks.append(ToolRunner.assetfinder(target))
            self.tools_used.add("assetfinder")
        
        # Built-in
        builtin = SubdomainEnumerator(target, self.config.threads)
        try:
            builtin_subs = await builtin.enumerate_all()
            all_subdomains.update(builtin_subs)
        except:
            pass
        
        if enum_tasks:
            tool_results = await asyncio.gather(*enum_tasks, return_exceptions=True)
            for s in tool_results:
                if isinstance(s, set):
                    all_subdomains.update(s)
        
        results["subdomains"] = sorted(all_subdomains)
        self._save_list(target_dir, "subdomains.txt", results["subdomains"])
        
        print(f"  Total unique subdomains: {len(results['subdomains'])}")
        
        if not results["subdomains"]:
            results["subdomains"] = [target]
        
        # ============ PHASE 2: URL & ENDPOINT DISCOVERY ============
        print("\n[Phase 2] URL & Endpoint Discovery (gau, katana, waybackurls)")
        all_urls = set()
        
        url_tasks = []
        if self.config.use_gau:
            url_tasks.append(ToolRunner.gau(target))
            self.tools_used.add("gau")
        if self.config.use_katana:
            url_tasks.append(ToolRunner.katana(target))
            self.tools_used.add("katana")
        if self.config.use_waybackurls:
            url_tasks.append(ToolRunner.waybackurls(target))
            self.tools_used.add("waybackurls")
        
        if url_tasks:
            url_results = await asyncio.gather(*url_tasks, return_exceptions=True)
            for s in url_results:
                if isinstance(s, set):
                    all_urls.update(s)
        
        results["urls"] = sorted(all_urls)
        self._save_list(target_dir, "urls.txt", results["urls"])
        print(f"  Total URLs: {len(results['urls'])}")
        
        # ============ PHASE 3: WHOIS & DNS ============
        print("\n[Phase 3] WHOIS & DNS Analysis")
        try:
            dns_analyzer = WhoisDNSAnalyzer(target)
            results["whois_dns"] = await dns_analyzer.analyze()
            print(f"  Registrar: {results['whois_dns']['whois'].get('registrar', 'N/A')}")
        except Exception as e:
            print(f"  [!] WHOIS error: {e}")
        
        # ============ PHASE 4: HTTP PROBING ============
        print("\n[Phase 4] HTTP Probing (httpx)")
        if self.config.use_httpx and results["subdomains"]:
            httpx_results = await ToolRunner.httpx(results["subdomains"])
            self.tools_used.add("httpx")
            results["alive_hosts"] = httpx_results
            self._save_dict_list(target_dir, "live_hosts.txt", httpx_results, 
                                lambda h, i: f"{i.get('url', h)} [{i.get('status', '?')}] {i.get('title', '')}")
        
        # Fallback
        if not results["alive_hosts"]:
            print("  Using built-in live host detector...")
            detector = LiveHostDetector(threads=self.config.threads)
            alive = await detector.check_all(results["subdomains"][:200])
            results["alive_hosts"] = {}
            for host, info in alive.items():
                results["alive_hosts"][host] = {
                    "url": info.get("urls", [None])[0] or f"https://{host}",
                    "status": list(info.get("status_codes", {}).values())[0] if info.get("status_codes") else 0,
                }
        
        print(f"  Live hosts: {len(results['alive_hosts'])}")
        
        # ============ PHASE 5: PORT & SERVICE DISCOVERY ============
        print("\n[Phase 5] Port & Service Discovery (naabu, nmap)")
        port_results = {}
        live_hosts = list(results["alive_hosts"].keys())[:20]
        
        if self.config.use_naabu:
            self.tools_used.add("naabu")
            naabu_tasks = [ToolRunner.naabu(host) for host in live_hosts]
            naabu_results = await asyncio.gather(*naabu_tasks, return_exceptions=True)
            for i, host in enumerate(live_hosts):
                if i < len(naabu_results) and isinstance(naabu_results[i], list):
                    port_results[host] = naabu_results[i]
        
        if self.config.use_nmap:
            self.tools_used.add("nmap")
            nmap_tasks = [ToolRunner.nmap_scan(host) for host in live_hosts[:5]]
            nmap_results = await asyncio.gather(*nmap_tasks, return_exceptions=True)
            for i, host in enumerate(live_hosts[:5]):
                if i < len(nmap_results) and isinstance(nmap_results[i], list) and nmap_results[i]:
                    if host not in port_results:
                        port_results[host] = []
                    port_results[host].extend(nmap_results[i])
        
        results["open_ports"] = port_results
        self._save_dict_list(target_dir, "ports.txt", port_results,
                            lambda h, p: f"{h}:{p['port']}/{p['service']}")
        
        print(f"  Total open ports: {sum(len(v) for v in port_results.values())}")
        
        # ============ PHASE 6: TECHNOLOGY DETECTION ============
        print("\n[Phase 6] Technology Detection")
        td = TechDetector()
        for host, info in list(results["alive_hosts"].items())[:50]:
            url = info.get("url", f"https://{host}")
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=10, ssl=False) as resp:
                        html = await resp.text()
                        techs = await td.detect(url, html, dict(resp.headers))
                        if techs:
                            results["technologies"][host] = techs
            except:
                pass
        
        # Merge httpx tech
        for host, info in results["alive_hosts"].items():
            if isinstance(info, dict) and info.get("tech"):
                if host not in results["technologies"]:
                    results["technologies"][host] = {}
                for t in info["tech"]:
                    if t not in results["technologies"][host]:
                        results["technologies"][host][t] = {"version": "Unknown", "confidence": 100, "evidence": ["httpx"]}
        
        print(f"  Technologies detected: {sum(len(v) for v in results['technologies'].values())}")
        
        # ============ PHASE 7: SSL ============
        print("\n[Phase 7] SSL Certificate Analysis")
        for host in live_hosts[:30]:
            try:
                ssl_info = await SSLAnalyzer(host, 443).analyze()
                if "error" not in ssl_info:
                    results["ssl_info"][host] = ssl_info
            except:
                pass
        print(f"  Certificates analyzed: {len(results['ssl_info'])}")
        
        # ============ PHASE 8: SUBDOMAIN TAKEOVER ============
        print("\n[Phase 8] Subdomain Takeover Detection")
        if results["subdomains"]:
            takeovers = await SubdomainTakeoverDetector(target).scan(results["subdomains"][:200])
            results["takeovers"] = takeovers
            if takeovers:
                print(f"  [!] {len(takeovers)} takeover vulnerabilities!")
                for t in takeovers:
                    print(f"    [HIGH] {t['subdomain']} -> {t['service']}")
                    # Notify immediately for critical findings
                    await self.notifier.send_critical_finding(
                        "Subdomain Takeover", t['subdomain'],
                        f"Service {t['service']} is unclaimed",
                        f"Claim via {t['cname']}"
                    )
            else:
                print("  No takeovers detected")
        
        # ============ PHASE 9: CONTENT DISCOVERY ============
        print("\n[Phase 9] Content Discovery & Fuzzing (ffuf, dirsearch, gobuster)")
        all_dirs = {}
        
        content_tasks = []
        for host in live_hosts[:3]:
            base_url = f"https://{host}"
            if self.config.use_ffuf:
                content_tasks.append(ToolRunner.ffuf(base_url))
                self.tools_used.add("ffuf")
            if self.config.use_dirsearch:
                content_tasks.append(ToolRunner.dirsearch(base_url))
                self.tools_used.add("dirsearch")
            if self.config.use_gobuster:
                content_tasks.append(ToolRunner.gobuster(base_url))
                self.tools_used.add("gobuster")
        
        if content_tasks:
            content_results = await asyncio.gather(*content_tasks, return_exceptions=True)
            for r in content_results:
                if isinstance(r, list):
                    for item in r:
                        url = item.get("url", "")
                        if url:
                            all_dirs[url] = {"status": item.get("status", "?"), "source": item.get("type", "unknown")}
        
        results["directories"] = all_dirs
        self._save_dict_list(target_dir, "directories.txt", all_dirs,
                            lambda u, i: f"{i['status']} - {u}")
        print(f"  Total paths found: {len(all_dirs)}")
        
        # ============ PHASE 10: PARAMETER & ENDPOINT DISCOVERY ============
        print("\n[Phase 10] Parameter & Endpoint Discovery (Arjun, LinkFinder)")
        if self.config.use_arjun and live_hosts:
            arjun_results = await ToolRunner.arjun(f"https://{live_hosts[0]}")
            self.tools_used.add("arjun")
        
        if self.config.use_linkfinder and live_hosts:
            linkfinder_results = await ToolRunner.linkfinder(f"https://{live_hosts[0]}")
            self.tools_used.add("linkfinder")
        
        # ============ PHASE 11: JS ANALYSIS ============
        print("\n[Phase 11] JavaScript Analysis")
        jc = JSCollector()
        async with aiohttp.ClientSession() as session:
            for host in live_hosts[:3]:
                url = results["alive_hosts"].get(host, {}).get("url", f"https://{host}")
                js_result = await jc.collect(url, session)
                if js_result["js_files"]:
                    results["js_analysis"].append(js_result)
                    sec_count = len(js_result.get("secrets", []))
                    if sec_count > 0:
                        print(f"  [SECRETS] {host}: {sec_count} secrets found!")
                    print(f"  {host}: {len(js_result['js_files'])} JS files")
        
        # ============ PHASE 12: VULNERABILITY SCANNING ============
        print("\n[Phase 12] Vulnerability Scanning (Nuclei, Nikto)")
        
        if self.config.use_nuclei and results["subdomains"]:
            nuclei_vulns = await ToolRunner.nuclei(results["subdomains"][:50])
            results["nuclei_vulns"] = nuclei_vulns
            self.tools_used.add("nuclei")
            if nuclei_vulns:
                self._save_list(target_dir, "nuclei_vulns.txt",
                              [f"[{v['severity'].upper()}] {v['name']} - {v['host']}" for v in nuclei_vulns])
                # Notify high severity
                for v in nuclei_vulns:
                    if v.get("severity", "").lower() in ["high", "critical"]:
                        await self.notifier.send_critical_finding(
                            "Nuclei: " + v['name'], v['host'],
                            v.get('description', '')[:100],
                            f"Check: {v.get('matched', '')}"
                        )
        
        if self.config.use_nikto and live_hosts:
            nikto_results = await ToolRunner.nikto(live_hosts[0])
            results["nikto_findings"] = nikto_results
            self.tools_used.add("nikto")
        
        # ============ PHASE 13: CLOUD & CONFIG REVIEW ============
        print("\n[Phase 13] Cloud & Configuration Review (TruffleHog, Gitleaks)")
        all_secrets = []
        
        if self.config.use_trufflehog:
            self.tools_used.add("trufflehog")
            # Scan JS files for secrets
            for js in results.get("js_analysis", []):
                for js_file in js.get("js_files", []):
                    secrets = await ToolRunner.trufflehog(js_file)
                    all_secrets.extend(secrets)
        
        if self.config.use_gitleaks:
            self.tools_used.add("gitleaks")
            # Scan the target directory
            secrets = await ToolRunner.gitleaks(target_dir)
            all_secrets.extend(secrets)
        
        results["secrets_found"] = all_secrets
        if all_secrets:
            self._save_list(target_dir, "secrets.txt",
                          [f"[{s.get('type','?')}] {s.get('secret','')[:80]}" for s in all_secrets])
            print(f"  [SECRETS] {len(all_secrets)} secrets/credentials found!")
            for s in all_secrets[:5]:
                await self.notifier.send_critical_finding(
                    "Secret Found", s.get('source', target),
                    f"Type: {s.get('type', 'Unknown')}",
                    f"Value: {s.get('secret', '')[:60]}"
                )
        
        results["end_time"] = datetime.now().isoformat()
        results["tools_used"] = sorted(self.tools_used)
        
        # ============ GENERATE REPORT ============
        print("\n[Phase 14] Generating Report")
        gen = ReportGenerator(target, target_dir)
        report_path = gen.generate_html(results)
        results["report_path"] = report_path
        print(f"  Report: {report_path}")
        
        return results
    
    def _save_list(self, directory: str, filename: str, items: List[str]):
        """Save a list to a file"""
        if not items:
            return
        path = os.path.join(directory, filename)
        with open(path, "w") as f:
            for item in items:
                f.write(f"{item}\n")
    
    def _save_dict_list(self, directory: str, filename: str, data: Dict, formatter):
        """Save a dict as formatted lines"""
        if not data:
            return
        path = os.path.join(directory, filename)
        with open(path, "w") as f:
            for key, value in data.items():
                if isinstance(value, list):
                    for item in value:
                        f.write(f"{formatter(key, item)}\n")
                else:
                    f.write(f"{formatter(key, value)}\n")
    
    async def run(self) -> Dict:
        """Run recon on all targets with Telegram notifications"""
        print(f"\n{'='*60}")
        print(f"  BBRecon v3.0 - Enterprise Multi-Target Scanner")
        print(f"{'='*60}")
        print(f"  Targets:    {', '.join(self.config.targets)}")
        print(f"  Threads:    {self.config.threads}")
        print(f"  Depth:      {self.config.depth}")
        
        # Check tools and notify
        tools_status = ToolRunner.get_installed_tools()
        available = sum(1 for v in tools_status.values() if v != "not found")
        print(f"  Tools:      {available}/{len(tools_status)} available")
        for name, status in sorted(tools_status.items()):
            icon = "✅" if status != "not found" else "❌"
            print(f"    {icon} {name}: {status[:50]}")
        print(f"{'='*60}\n")
        
        # Notify scan start
        await self.notifier.send_scan_start(self.config.targets, available)
        
        os.makedirs(self.config.output_dir, exist_ok=True)
        
        # Scan all targets
        for target in self.config.targets:
            self.all_results[target] = await self.scan_target(target)
        
        # Generate master summary
        elapsed = datetime.now() - self.start_time
        mins = int(elapsed.total_seconds() // 60)
        secs = int(elapsed.total_seconds() % 60)
        
        total_subs = sum(len(r.get("subdomains", [])) for r in self.all_results.values())
        total_takeovers = sum(len(r.get("takeovers", [])) for r in self.all_results.values())
        total_vulns = sum(len(r.get("nuclei_vulns", [])) for r in self.all_results.values())
        total_secrets = sum(len(r.get("secrets_found", [])) for r in self.all_results.values())
        
        print(f"\n{'='*60}")
        print(f"  MASTER SCAN COMPLETE - {mins}m {secs}s")
        print(f"{'='*60}")
        print(f"  Targets:     {len(self.config.targets)}")
        print(f"  Subdomains:  {total_subs}")
        print(f"  Takeovers:   {total_takeovers}")
        print(f"  Vulns:       {total_vulns}")
        print(f"  Secrets:     {total_secrets}")
        print(f"  Tools Used:  {', '.join(sorted(self.tools_used))}")
        print(f"  Reports:     {os.path.abspath(self.config.output_dir)}")
        print(f"{'='*60}\n")
        
        # Notify scan complete
        await self.notifier.send_scan_complete(self.all_results)
        
        # Actionable summary
        if total_takeovers > 0:
            print("  🚨 HIGH PRIORITY - Subdomain Takeovers:")
            for _, r in self.all_results.items():
                for t in r.get("takeovers", []):
                    print(f"     {t['subdomain']} -> {t['service']}")
        
        if total_secrets > 0:
            print("  🔑 SECRETS FOUND - Check individual reports")
        
        if total_vulns > 0:
            print("  ⚠️ VULNERABILITIES FOUND - Review nuclei output")
        
        print(f"\n  📊 Dashboard: python main.py --web-only --port 8080")
        print(f"  📁 Reports:   {os.path.abspath(self.config.output_dir)}\n")
        
        return self.all_results
