#!/usr/bin/env python3
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import asyncio
import argparse
from config import Config
from core.scanner import ReconScanner
from core.tool_runner import ToolRunner

def main():
    parser = argparse.ArgumentParser(
        description="BBRecon v3.0 - Enterprise Bug Bounty Reconnaissance Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  Basic:
    python main.py -d example.com
    python main.py -d example.com,test.com

  Modes:
    python main.py -d example.com --quick        # Fast scan
    python main.py -d example.com --full         # All tools (ZAP, amass, nikto)
    python main.py -d example.com --sql          # Include SQL injection

  Custom:
    python main.py -d example.com -l subs.txt    # Custom subdomain list
    python main.py -d example.com -t 100         # More threads
    python main.py --targets targets.txt         # Targets from file

  Telegram:
    TELEGRAM_BOT_TOKEN=x TELEGRAM_CHAT_ID=y python main.py -d example.com

  Dashboard:
    python main.py --web-only --port 8080

  Tool Check:
    python main.py --check-tools                # Show installed tools

POPULAR BUG BOUNTY STACK (2026):
  Subfinder -> httpx -> Katana -> ffuf -> Nuclei -> Nmap -> Manual validation

TOOLS INTEGRATED (18):
  Subdomain:   subfinder, amass, assetfinder
  URLs:        gau, katana, waybackurls
  Ports:       naabu, nmap
  HTTP:        httpx (tech detect, titles, status codes)
  Vulns:       nuclei, nikto, OWASP ZAP
  SQLi:        sqlmap
  Fuzzing:     ffuf, dirsearch, gobuster
  Parameters:  arjun, LinkFinder
  Secrets:     trufflehog, gitleaks

TELEGRAM SETUP:
  1. Create bot: https://t.me/BotFather -> /newbot -> save token
  2. Get chat ID: Message @userinfobot -> save ID
  3. Run: TELEGRAM_BOT_TOKEN="xxx" TELEGRAM_CHAT_ID="yyy" python main.py -d example.com
        """
    )
    parser.add_argument("-d", "--domain", help="Target domain(s) - comma separated")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Thread count (default: 50)")
    parser.add_argument("-o", "--output", default="./results", help="Output directory")
    parser.add_argument("-w", "--wordlist", default="./wordlists/directory.txt", help="Directory wordlist")
    parser.add_argument("-l", "--subdomain-list", help="Custom subdomain list file")
    parser.add_argument("--targets", help="File containing list of targets")
    parser.add_argument("--quick", action="store_true", help="Quick scan (skip slow tools)")
    parser.add_argument("--full", action="store_true", help="Full scan (all tools)")
    parser.add_argument("--sql", action="store_true", help="Include SQL injection testing")
    parser.add_argument("--telegram", action="store_true", help="Enable Telegram notifications")
    parser.add_argument("--web", action="store_true", help="Start dashboard after scan")
    parser.add_argument("--web-only", action="store_true", help="Dashboard only (no scan)")
    parser.add_argument("--port", type=int, default=5000, help="Dashboard port")
    parser.add_argument("--check-tools", action="store_true", help="Check installed tools and exit")
    args = parser.parse_args()

    # Check tools mode
    if args.check_tools:
        print("\n[*] Checking installed tools...\n")
        tools = ToolRunner.get_installed_tools()
        for name, status in sorted(tools.items()):
            icon = "✅" if status != "not found" else "❌"
            print(f"  {icon} {name}: {status[:80]}")
        print(f"\n  Available: {sum(1 for v in tools.values() if v != 'not found')}/{len(tools)}")
        return

    # Web dashboard only
    if args.web_only:
        print("[*] Starting BBRecon Dashboard...")
        print(f"[*] Open http://127.0.0.1:{args.port} in your browser")
        from web.app import app
        app.run(host="0.0.0.0", port=args.port, debug=False)
        return

    # Collect targets
    targets = []
    if args.targets:
        with open(args.targets) as f:
            targets = [line.strip() for line in f if line.strip()]
    elif args.domain:
        targets = [d.strip() for d in args.domain.split(",")]
    
    if not targets:
        print("[!] No targets. Use -d example.com or --targets file.txt")
        parser.print_help()
        sys.exit(1)
    
    print(f"[*] Targets: {len(targets)} domains loaded")
    
    config = Config(
        targets=targets,
        threads=args.threads,
        output_dir=args.output,
        wordlist=args.wordlist,
        subdomain_list=args.subdomain_list,
    )
    
    # Quick mode
    if args.quick:
        config.use_amass = False
        config.use_nmap = False
        config.use_nuclei = False
        config.use_nikto = False
        config.use_zap = False
        config.use_sqlmap = False
        config.use_trufflehog = False
        config.use_gitleaks = False
        config.depth = "quick"
        print("[*] Quick mode - heavy tools disabled")
    
    # Full mode
    if args.full:
        config.use_amass = True
        config.use_nmap = True
        config.use_nikto = True
        config.use_zap = True
        config.depth = "full"
        print("[*] Full mode - all tools enabled")
    
    # SQL mode
    if args.sql:
        config.use_sqlmap = True
        print("[*] SQL injection testing enabled")
    
    # Telegram
    if args.telegram:
        if not config.telegram_bot_token or not config.telegram_chat_id:
            print("[!] Telegram requires env vars:")
            print("    TELEGRAM_BOT_TOKEN='token' TELEGRAM_CHAT_ID='id'")
            sys.exit(1)
        print("[*] Telegram notifications active")

    # Print config
    print(f"""
    {'='*52}
      BBRecon v3.0 - Enterprise Recon
    {'='*52}
      Targets:    {len(targets)} domain(s)
      Threads:    {config.threads}
      Output:     {config.output_dir}
      Mode:       {config.depth}
      Telegram:   {"✅" if config.telegram_bot_token else "❌"}
    {'='*52}
    """)
    
    scanner = ReconScanner(config)
    try:
        asyncio.run(scanner.run())
        if args.web:
            print(f"[*] Starting dashboard on port {args.port}...")
            from web.app import app
            app.run(host="0.0.0.0", port=args.port, debug=False)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(0)

if __name__ == "__main__":
    main()
