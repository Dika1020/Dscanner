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

## 🚀 Instalasi

### 1. Clone Repository

```bash
git clone https://github.com/username/DScanner.git
cd DScanner
pip install -r requirements.txt

```bash
🚀 Quick Start — Tutorial Command
