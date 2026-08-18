import asyncio
import os
import subprocess
import json
from typing import List, Set, Dict, Optional, Any

class ToolRunner:
    """Async wrapper for ALL external security tools"""
    
    @staticmethod
    async def run(cmd: List[str], timeout: int = 120, shell: bool = False) -> str:
        """Run a command asynchronously and return stdout"""
        try:
            if shell:
                proc = await asyncio.create_subprocess_shell(
                    " ".join(cmd) if isinstance(cmd, list) else cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            else:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                return stdout.decode(errors='ignore')
            except asyncio.TimeoutError:
                proc.kill()
                return ""
        except FileNotFoundError:
            return ""
        except Exception as e:
            return ""
    
    @staticmethod
    def check_tool(name: str) -> bool:
        """Check if a tool is installed"""
        try:
            subprocess.run(["which", name], capture_output=True, timeout=3, check=True)
            return True
        except:
            return False

    # ==================== SUBDOMAIN ENUMERATION ====================
    
    @staticmethod
    async def subfinder(domain: str) -> Set[str]:
        results = set()
        if not ToolRunner.check_tool("subfinder"):
            print("    [!] subfinder not installed. Run: sudo apt install subfinder")
            return results
        try:
            output = await ToolRunner.run(["subfinder", "-d", domain, "-silent"])
            for line in output.strip().split("\n"):
                if line.strip():
                    results.add(line.strip().lower())
            print(f"    [subfinder] {len(results)} subdomains")
        except Exception as e:
            print(f"    [subfinder] Error: {e}")
        return results
    
    @staticmethod
    async def amass(domain: str) -> Set[str]:
        results = set()
        if not ToolRunner.check_tool("amass"):
            return results
        try:
            output = await ToolRunner.run(["amass", "enum", "-passive", "-d", domain, "-quiet"], timeout=300)
            for line in output.strip().split("\n"):
                if line.strip() and domain in line:
                    results.add(line.strip().lower())
            print(f"    [amass] {len(results)} subdomains")
        except:
            pass
        return results
    
    @staticmethod
    async def assetfinder(domain: str) -> Set[str]:
        results = set()
        if not ToolRunner.check_tool("assetfinder"):
            return results
        try:
            output = await ToolRunner.run(["assetfinder", "--subs-only", domain])
            for line in output.strip().split("\n"):
                if line.strip():
                    results.add(line.strip().lower())
            print(f"    [assetfinder] {len(results)} subdomains")
        except:
            pass
        return results

    # ==================== URL & ENDPOINT DISCOVERY ====================
    
    @staticmethod
    async def gau(domain: str) -> Set[str]:
        results = set()
        if not ToolRunner.check_tool("gau"):
            print("    [!] gau not installed. Run: go install github.com/lc/gau/v2/cmd/gau@latest")
            return results
        try:
            output = await ToolRunner.run(["gau", "--subs", domain], timeout=180)
            for line in output.strip().split("\n"):
                if line.strip():
                    results.add(line.strip())
            print(f"    [gau] {len(results)} URLs")
        except:
            pass
        return results
    
    @staticmethod
    async def waybackurls(domain: str) -> Set[str]:
        results = set()
        if not ToolRunner.check_tool("waybackurls"):
            return results
        try:
            output = await ToolRunner.run(["waybackurls", domain], timeout=120)
            for line in output.strip().split("\n"):
                if line.strip():
                    results.add(line.strip())
            print(f"    [waybackurls] {len(results)} URLs")
        except:
            pass
        return results
    
    @staticmethod
    async def katana(domain: str) -> Set[str]:
        results = set()
        if not ToolRunner.check_tool("katana"):
            print("    [!] katana not installed")
            return results
        try:
            output = await ToolRunner.run(["katana", "-u", f"https://{domain}", "-silent", "-jc", "-kf", "-d", "3"], timeout=120)
            for line in output.strip().split("\n"):
                if line.strip():
                    results.add(line.strip())
            print(f"    [katana] {len(results)} endpoints")
        except:
            pass
        return results

    # ==================== PORT & SERVICE DISCOVERY ====================
    
    @staticmethod
    async def naabu(host: str) -> List[Dict]:
        results = []
        if not ToolRunner.check_tool("naabu"):
            return results
        try:
            output = await ToolRunner.run(["naabu", "-host", host, "-top-ports", "100", "-silent"], timeout=60)
            for line in output.strip().split("\n"):
                if ":" in line:
                    parts = line.strip().split(":")
                    if len(parts) == 2:
                        results.append({"host": parts[0], "port": int(parts[1]), "service": "unknown"})
            print(f"    [naabu] {host}: {len(results)} open ports")
        except:
            pass
        return results
    
    @staticmethod
    async def nmap_scan(host: str, ports: str = "21,22,25,53,80,110,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,9000,27017") -> List[Dict]:
        results = []
        if not ToolRunner.check_tool("nmap"):
            return results
        try:
            output = await ToolRunner.run(["nmap", "-sV", "-p", ports, "--open", "-T4", host], timeout=180)
            for line in output.split("\n"):
                if "/tcp" in line and "open" in line:
                    parts = line.strip().split()
                    port = int(parts[0].split("/")[0])
                    service = parts[2] if len(parts) > 2 else "unknown"
                    version = parts[2] if len(parts) > 3 else ""
                    results.append({"host": host, "port": port, "service": service, "version": version})
            print(f"    [nmap] {host}: {len(results)} services")
        except:
            pass
        return results

    # ==================== HTTP PROBING ====================
    
    @staticmethod
    async def httpx(hosts: List[str]) -> Dict[str, Dict]:
        results = {}
        tool = "httpx-toolkit" if ToolRunner.check_tool("httpx-toolkit") else ("httpx" if ToolRunner.check_tool("httpx") else None)
        if not tool:
            print("    [!] httpx not installed. Run: sudo apt install httpx-toolkit")
            return results
        
        temp_file = "/tmp/bbrecon_httpx.txt"
        with open(temp_file, "w") as f:
            for h in hosts[:300]:
                f.write(f"{h}\n")
        
        try:
            output = await ToolRunner.run([tool, "-l", temp_file, "-silent", "-title", "-tech-detect", "-status-code", "-json"], timeout=180)
            for line in output.strip().split("\n"):
                if line.strip():
                    try:
                        data = json.loads(line)
                        host = data.get("host", "")
                        results[host] = {
                            "url": data.get("url", ""),
                            "status": data.get("status_code", 0),
                            "title": data.get("title", ""),
                            "tech": data.get("tech", []),
                            "content_length": data.get("content_length", 0),
                            "webserver": data.get("webserver", ""),
                        }
                    except:
                        pass
            print(f"    [httpx] {len(results)} live hosts")
        except:
            pass
        if os.path.exists(temp_file):
            os.remove(temp_file)
        return results

    # ==================== VULNERABILITY SCANNERS ====================
    
    @staticmethod
    async def nuclei(hosts: List[str], severity: str = "medium,high,critical") -> List[Dict]:
        results = []
        if not ToolRunner.check_tool("nuclei"):
            print("    [!] nuclei not installed. Run: sudo apt install nuclei")
            return results
        
        temp_file = "/tmp/bbrecon_nuclei.txt"
        with open(temp_file, "w") as f:
            for h in hosts[:50]:
                f.write(f"{h}\n")
        
        try:
            output = await ToolRunner.run(["nuclei", "-l", temp_file, "-severity", severity, "-silent", "-json", "-rate-limit", "50"], timeout=300)
            for line in output.strip().split("\n"):
                if line.strip():
                    try:
                        data = json.loads(line)
                        results.append({
                            "template": data.get("template-id", ""),
                            "name": data.get("info", {}).get("name", ""),
                            "severity": data.get("info", {}).get("severity", ""),
                            "host": data.get("host", ""),
                            "matched": data.get("matched-at", ""),
                            "description": data.get("info", {}).get("description", ""),
                            "type": "nuclei"
                        })
                    except:
                        pass
            print(f"    [nuclei] {len(results)} vulnerabilities")
        except:
            pass
        if os.path.exists(temp_file):
            os.remove(temp_file)
        return results
    
    @staticmethod
    async def nikto(host: str) -> List[Dict]:
        results = []
        if not ToolRunner.check_tool("nikto"):
            print("    [!] nikto not installed. Run: sudo apt install nikto")
            return results
        try:
            output = await ToolRunner.run(["nikto", "-h", host, "-ssl", "-Format", "json", "-nointeractive"], timeout=300)
            for line in output.split("\n"):
                if "OSVDB" in line or "+" in line:
                    results.append({"host": host, "finding": line.strip(), "type": "nikto"})
            print(f"    [nikto] {host}: {len(results)} findings")
        except:
            pass
        return results
    
    @staticmethod
    async def zap_scan(target_url: str) -> List[Dict]:
        """OWASP ZAP - requires ZAP running in daemon mode"""
        results = []
        if not ToolRunner.check_tool("zap.sh") and not ToolRunner.check_tool("zap"):
            print("    [!] ZAP not found. Run: sudo apt install zaproxy")
            return results
        
        # Check if ZAP is running in daemon mode
        try:
            # First try the API
            import aiohttp
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get("http://localhost:8080/JSON/core/view/version/", timeout=5) as resp:
                        if resp.status == 200:
                            print("    [ZAP] Daemon detected on port 8080")
                            # Start spider
                            async with session.get(f"http://localhost:8080/JSON/spider/action/scan/?url={target_url}&maxChildren=5") as resp:
                                data = await resp.json()
                                scan_id = data.get("scan", "")
                                print(f"    [ZAP] Spider started: ID {scan_id}")
                            # Wait and get results
                            await asyncio.sleep(10)
                            async with session.get(f"http://localhost:8080/JSON/core/view/alerts/?baseurl={target_url}") as resp:
                                alerts = await resp.json()
                                for alert in alerts.get("alerts", []):
                                    results.append({
                                        "host": target_url,
                                        "name": alert.get("alert", ""),
                                        "risk": alert.get("risk", ""),
                                        "description": alert.get("description", ""),
                                        "solution": alert.get("solution", ""),
                                        "type": "zap"
                                    })
                            print(f"    [ZAP] {len(results)} alerts")
                except:
                    print("    [ZAP] Daemon not running. Start with: zap.sh -daemon -port 8080")
        except:
            pass
        return results

    # ==================== SQL INJECTION ====================
    
    @staticmethod
    async def sqlmap(target_url: str) -> List[Dict]:
        results = []
        if not ToolRunner.check_tool("sqlmap"):
            print("    [!] sqlmap not installed. Run: sudo apt install sqlmap")
            return results
        try:
            output = await ToolRunner.run(["sqlmap", "-u", target_url, "--batch", "--level", "1", "--risk", "1"], timeout=300)
            for line in output.split("\n"):
                if "Parameter:" in line or "Type:" in line or "injectable" in line.lower():
                    results.append({"host": target_url, "finding": line.strip(), "type": "sqlmap"})
            print(f"    [sqlmap] {target_url}: {len(results)} findings")
        except:
            pass
        return results

    # ==================== CONTENT DISCOVERY & FUZZING ====================
    
    @staticmethod
    async def ffuf(target_url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> List[Dict]:
        results = []
        if not ToolRunner.check_tool("ffuf"):
            print("    [!] ffuf not installed. Run: sudo apt install ffuf")
            return results
        if not os.path.exists(wordlist):
            wordlist = "/usr/share/wordlists/dirb/common.txt"
        if not os.path.exists(wordlist):
            return results
        try:
            output = await ToolRunner.run(["ffuf", "-u", f"{target_url}/FUZZ", "-w", wordlist, "-t", "50", "-c", "-s"], timeout=120)
            for line in output.strip().split("\n"):
                if line.strip():
                    try:
                        # ffuf -s output format
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            results.append({"url": parts[-1], "status": parts[0], "type": "ffuf"})
                    except:
                        results.append({"url": line.strip(), "status": "?", "type": "ffuf"})
            print(f"    [ffuf] {target_url}: {len(results)} paths")
        except:
            pass
        return results
    
    @staticmethod
    async def dirsearch(target_url: str) -> List[Dict]:
        results = []
        if not ToolRunner.check_tool("dirsearch"):
            print("    [!] dirsearch not installed. Run: sudo apt install dirsearch")
            return results
        try:
            output = await ToolRunner.run(["dirsearch", "-u", target_url, "--random-agent", "--timeout", "3", "--max-rate", "50"], timeout=120)
            for line in output.split("\n"):
                if "] /" in line or "] 2" in line:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        status = parts[0].replace("[", "").replace("]", "")
                        url = parts[-1]
                        results.append({"url": url, "status": status, "type": "dirsearch"})
            print(f"    [dirsearch] {target_url}: {len(results)} paths")
        except:
            pass
        return results
    
    @staticmethod
    async def gobuster(target_url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> List[Dict]:
        results = []
        if not ToolRunner.check_tool("gobuster"):
            print("    [!] gobuster not installed. Run: sudo apt install gobuster")
            return results
        if not os.path.exists(wordlist):
            return results
        try:
            output = await ToolRunner.run(["gobuster", "dir", "-u", target_url, "-w", wordlist, "-t", "50", "-q", "-n"], timeout=120)
            for line in output.strip().split("\n"):
                if "Status:" in line:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        results.append({"url": parts[0].rstrip("/"), "status": parts[3], "type": "gobuster"})
            print(f"    [gobuster] {target_url}: {len(results)} paths")
        except:
            pass
        return results

    # ==================== PARAMETER & ENDPOINT DISCOVERY ====================
    
    @staticmethod
    async def arjun(target_url: str) -> List[str]:
        results = []
        if not ToolRunner.check_tool("arjun"):
            print("    [!] arjun not installed. Run: pip install arjun")
            return results
        try:
            output = await ToolRunner.run(["arjun", "-u", target_url, "--quiet"], timeout=120)
            for line in output.strip().split("\n"):
                if "Parameters found" in line or "param" in line.lower():
                    results.append(line.strip())
            print(f"    [arjun] {target_url}: parameter discovery complete")
        except:
            pass
        return results
    
    @staticmethod
    async def linkfinder(target_url: str) -> List[str]:
        """Extract endpoints from JS files using LinkFinder patterns"""
        import re
        results = []
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(target_url, timeout=10, ssl=False) as resp:
                    html = await resp.text()
                    # Find JS files
                    js_pattern = re.compile(r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
                    for match in js_pattern.finditer(html):
                        js_url = match.group(1)
                        if not js_url.startswith("http"):
                            from urllib.parse import urljoin
                            js_url = urljoin(target_url, js_url)
                        try:
                            async with session.get(js_url, timeout=10, ssl=False) as js_resp:
                                js_content = await js_resp.text()
                                # Extract endpoints
                                endpoints = re.findall(r'["\'](/[a-zA-Z0-9_\-./?&=#]+)["\']', js_content)
                                for ep in endpoints:
                                    if any(x in ep.lower() for x in ['api', 'v1', 'v2', 'graphql', 'rest', 'endpoint']):
                                        results.append(ep)
                        except:
                            pass
            print(f"    [LinkFinder] {target_url}: {len(results)} endpoints")
        except:
            pass
        return results

    # ==================== CLOUD & CONFIGURATION REVIEW ====================
    
    @staticmethod
    async def trufflehog(path: str) -> List[Dict]:
        results = []
        if not ToolRunner.check_tool("trufflehog"):
            print("    [!] trufflehog not installed. Run: pipx install trufflehog")
            return results
        try:
            if os.path.isdir(path):
                output = await ToolRunner.run(["trufflehog", "filesystem", path, "--json", "--no-update"], timeout=300)
            else:
                output = await ToolRunner.run(["trufflehog", "git", path, "--json", "--no-update"], timeout=300)
            for line in output.strip().split("\n"):
                if line.strip():
                    try:
                        data = json.loads(line)
                        results.append({
                            "source": data.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("url", str(path)),
                            "secret": data.get("Raw", "")[:80],
                            "type": data.get("DetectorType", "Unknown"),
                            "path": data.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("file", ""),
                            "severity": "high",
                            "finder": "trufflehog"
                        })
                    except:
                        pass
            print(f"    [trufflehog] {len(results)} secrets found")
        except:
            pass
        return results
    
    @staticmethod
    async def gitleaks(path: str) -> List[Dict]:
        results = []
        if not ToolRunner.check_tool("gitleaks"):
            print("    [!] gitleaks not installed. Run: go install github.com/gitleaks/gitleaks/v8@latest")
            return results
        try:
            if os.path.isdir(path):
                output = await ToolRunner.run(["gitleaks", "detect", "--source", path, "--no-git", "--verbose", "--no-color"], timeout=180)
            else:
                output = await ToolRunner.run(["gitleaks", "detect", "--source", path, "--verbose", "--no-color"], timeout=180)
            for line in output.strip().split("\n"):
                if "Secret" in line or "leak" in line.lower():
                    results.append({"finding": line.strip(), "severity": "high", "finder": "gitleaks"})
            print(f"    [gitleaks] {len(results)} leaks found")
        except:
            pass
        return results

    # ==================== TOOL VERSION CHECK ====================
    
    @staticmethod
    def get_installed_tools() -> Dict[str, str]:
        """Check which tools are available and their versions"""
        tools = {
            "subfinder": "subfinder -version 2>&1 | head -1",
            "amass": "amass -version 2>&1 | head -1",
            "assetfinder": "assetfinder -h 2>&1 | head -1",
            "gau": "gau --version 2>&1 | head -1",
            "katana": "katana -version 2>&1 | head -1",
            "waybackurls": "waybackurls -h 2>&1 | head -1",
            "naabu": "naabu -version 2>&1 | head -1",
            "nmap": "nmap --version 2>&1 | head -1",
            "httpx-toolkit": "httpx-toolkit -version 2>&1 | head -1",
            "nuclei": "nuclei -version 2>&1 | head -1",
            "nikto": "nikto -Version 2>&1 | head -1",
            "sqlmap": "sqlmap --version 2>&1 | head -1",
            "ffuf": "ffuf -V 2>&1 | head -1",
            "dirsearch": "dirsearch --version 2>&1 | head -1",
            "gobuster": "gobuster --version 2>&1 | head -1",
            "arjun": "arjun --version 2>&1 | head -1",
            "trufflehog": "trufflehog --version 2>&1 | head -1",
            "gitleaks": "gitleaks --version 2>&1 | head -1",
        }
        results = {}
        for name, cmd in tools.items():
            try:
                output = subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
                version = output.stdout.decode().strip() or output.stderr.decode().strip() or "installed"
                results[name] = version[:80]
            except:
                results[name] = "not found"
        return results
