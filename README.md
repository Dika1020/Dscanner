# 🔍 DScanner — WAF Detector + Parameter Finder + Payload Recommender

**DScanner** is a reconnaissance tool designed to detect Web Application Firewalls (WAFs), identify hidden parameters, and provide payload recommendations based on the parameters found.

<div align="center">

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)

</div>

---

## 🎯 Fitur

- ✅ **WAF Detection** — Detects 12+ WAFs (Cloudflare, F5, AWS, Alibaba, Imperva, etc.)
- ✅ **Parameter Discovery** — Finds parameters from URLs, HTML, JavaScript, and fuzzing
- ✅ **Auto Collab** — Automatically uses `waybackurls`, `gau`, `paramspider`, and `ffuf` if installed
- ✅ **Payload Recommendation** — Recommends vulnerability types based on parameter names
- ✅ **CLI Support** — Can be run with arguments for red team activities or automation
- ✅ **Interactive Mode** — Easy to use with an interactive prompt
- ✅ **JSON Output** — For integration with other tools
- ✅ **Cross-platform** — Windows, Linux, macOS


# Collab Tools
sudo apt install ffuf -y
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
pip install paramspider

---
## ☕ Support the Project

If you find DScanner useful, consider supporting its development:

### International
- [PayPal](https://paypal.me/indka23)

### Indonesia (Lokal)
- [Saweria](https://saweria.co/Dikaputra12)


## 🚀 Instalasi

### 1. Clone Repository



```bash
git clone https://github.com/username/DScanner.git
cd DScanner
pip install -r requirements.txt
---
# Interactive mode (easiest for beginners)
python dscanner.py

# Direct scan with URL
python dscanner.py -u https://example.com

# Scan with JSON output (for automation)
python dscanner.py -u https://example.com --json

# Only detect WAF (skip parameter discovery)
python dscanner.py -u https://example.com --waf-only

# Only discover parameters (skip WAF detection)
python dscanner.py -u https://example.com --params-only

# Disable colored output (for logs)
python dscanner.py -u https://example.com --no-color

# Show all available options
python dscanner.py --help

$ python dscanner.py -u https://www.example.com/

   ╔══════════════════════════════════════════════════════════════╗
  ║  ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ ║
  ║  ██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗║
  ║  ██║  ██║███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝║
  ║  ██║  ██║╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗║
  ║  ██████╔╝███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║║
  ║  ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝║
  ║  🔍 WAF Detector + Parameter Finder + Payload Recommender
  ║  📡 v4.1 — Auto Collab + CLI — by Dka                 
  ╚══════════════════════════════════════════════════════════════╝

  ─── SCANNING TARGET ───
  URL: https://www.example.com/

  ─── WAF DETECTION ───
  ✔ WAF detected: alibaba
  HTTP Status: 307

  ─── PARAMETER DISCOVERY ───
  ✔ Found 1 parameter(s) (URL: 1)
  MUTATE] Bypass cityEnName [01/01] [PASSED]
    → cityEnName = JKT (URL)

  ─── PAYLOAD RECOMMENDATION ───
  MUTATE] Bypass cityEnName [01/01] [PASSED]
    → Suitable for: [SQLi, XSS]

  ─── SUMMARY ───
  URL          : https://www.example.com/
  Status       : 307
  WAF          : alibaba
  Parameters   : 1

  ✅ Done.

