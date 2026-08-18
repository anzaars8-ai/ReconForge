#!/bin/bash
set -e
echo "=============================="
echo " BBRecon v3.0 — Tool Installer"
echo "=============================="
echo ""

# Update system
sudo apt update -y && sudo apt upgrade -y

# Go tools (ProjectDiscovery + others)
tools_go=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/tomnomnom/assetfinder@latest"
  "github.com/lc/gau/v2/cmd/gau@latest"
  "github.com/projectdiscovery/katana/cmd/katana@latest"
  "github.com/tomnomnom/waybackurls@latest"
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "github.com/OJ/gobuster/v3@latest"
  "github.com/ffuf/ffuf/v2@latest"
)

echo "[+] Installing Go tools..."
for t in "${tools_go[@]}"; do
  name=$(echo "$t" | awk -F'/' '{print $(NF-2)}')
  if command -v "$name" &>/dev/null; then echo "  ✅ $name already installed"; else echo "  📦 Installing $name..."; go install -v "$t" 2>/dev/null || echo "  ⚠️ Failed: $name"; fi
done

# Pip tools
echo ""
echo "[+] Installing Python tools..."
pip3 install --upgrade pip 2>/dev/null
pip3 install theHarvester linkfinder flask aiohttp 2>/dev/null || echo "  ⚠️ Some pip installs failed"

# Apt tools
echo ""
echo "[+] Installing apt tools..."
sudo apt install -y nmap nikto sqlmap dirsearch recon-ng 2>/dev/null || echo "  ⚠️ Some apt installs failed"

# Nuclei templates
echo ""
if command -v nuclei &>/dev/null; then
  echo "[+] Updating nuclei templates..."
  nuclei -update-templates 2>/dev/null || echo "  ⚠️ Template update failed"
fi

# Gitleaks
if ! command -v gitleaks &>/dev/null; then
  echo "[+] Installing gitleaks..."
  go install github.com/gitleaks/gitleaks/v8@latest 2>/dev/null || echo "  ⚠️ gitleaks failed"
fi

# TruffleHog
if ! command -v trufflehog &>/dev/null; then
  echo "[+] Installing trufflehog..."
  pip3 install trufflehog 2>/dev/null || \
  curl -sL https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_Linux_x86_64.tar.gz -o /tmp/th.tar.gz && \
  tar xzf /tmp/th.tar.gz -C /usr/local/bin/ trufflehog 2>/dev/null || echo "  ⚠️ trufflehog failed"
fi

# Ensure Go bin in PATH
if ! echo "$PATH" | grep -q "$HOME/go/bin"; then
  echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
  export PATH=$PATH:$HOME/go/bin
fi

# Arjun
if ! command -v arjun &>/dev/null; then
  echo "[+] Installing arjun..."
  pip3 install arjun 2>/dev/null || echo "  ⚠️ arjun failed"
fi

echo ""
echo "=============================="
echo " ✅ Installation Complete!"
echo "=============================="
echo ""
echo "Run: python main.py --check-tools"
echo "Then: python main.py -d example.com --quick"
