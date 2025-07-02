# BackdoorBuster

**Advanced Cross-Platform Malware Detection Tool**

*Created by [Shieldpy](https://shieldpy.com) - Professional Cybersecurity Solutions*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)](https://github.com/Qixpy/BackdoorBuster)

## 🛠️ Fix: Permission Denied During Installation

If you see an error like:

```bash
❌ Failed to copy config template: [Errno 13] Permission denied: '/home/youruser/BackdoorBuster/config.json'
```

It means some files were created with sudo and are now owned by root, blocking normal access.

**✅ Solution (run this):**
```bash
sudo chown -R $USER:$USER ~/BackdoorBuster
```

Then activate your virtual environment and reinstall:

```bash
source venv/bin/activate
python3 install.py
```

**🚫 Do NOT use sudo inside venv**

Never run `sudo python3 install.py` — it breaks your virtual environment.

*Stay clean. Stay in userland.*  
— Shieldpy Team

## 🔄 How to Update BackdoorBuster

### **Quick Update (Recommended):**
```bash
cd ~/BackdoorBuster
git pull origin main
```

### **Update with Dependencies:**
```bash
cd ~/BackdoorBuster
git pull origin main

# If using virtual environment
source venv/bin/activate
pip install --upgrade -r requirements_core.txt

# If using system packages
pip3 install --user --upgrade Flask Jinja2 termcolor psutil
```

### **Kali Linux Update:**
```bash
cd ~/BackdoorBuster
git pull origin main
chmod +x *.sh
./install_kali.sh  # Re-run installer to get latest features
```

### **Force Clean Update (if issues):**
```bash
cd ~
rm -rf BackdoorBuster
git clone https://github.com/Qixpy/BackdoorBuster.git
cd BackdoorBuster
chmod +x install_kali.sh && ./install_kali.sh
```

### **Check Version:**
```bash
python3 main.py --version
```

---
## Overview

BackdoorBuster is a comprehensive malware detection and analysis tool designed for cybersecurity professionals. It provides both command-line and web-based interfaces for scanning, analyzing, and managing potential security threats across multiple platforms.

## Features

- 🔍 **Advanced Scanning**: File and directory malware detection
- 🌐 **Web Interface**: Browser-based log viewer and analysis dashboard
- 🖥️ **Cross-Platform**: Works on Windows, macOS, and Linux
- 📊 **Multiple Output Formats**: JSON, HTML, and PDF reports
- 🛡️ **YARA Integration**: Custom rule-based detection (optional)
- 💾 **Database Support**: PostgreSQL integration for data persistence (optional)
- 🔒 **Security Features**: Encryption support and secure quarantine
- 📈 **Real-time Monitoring**: System monitoring capabilities

## Quick Start

### Installation

**Windows (PowerShell):**
```powershell
git clone https://github.com/Qixpy/BackdoorBuster.git
cd BackdoorBuster
.\install.ps1
```

**Windows (Batch):**
```cmd
git clone https://github.com/Qixpy/BackdoorBuster.git
cd BackdoorBuster
install.bat
```

**macOS/Linux:**
```bash
git clone https://github.com/Qixpy/BackdoorBuster.git
cd BackdoorBuster
chmod +x install.sh && ./install.sh
```

**Kali Linux (Recommended):**
```bash
git clone https://github.com/Qixpy/BackdoorBuster.git
cd BackdoorBuster
chmod +x install_kali.sh && ./install_kali.sh
```

**Kali Linux (Simple - if main installer fails):**
```bash
git clone https://github.com/Qixpy/BackdoorBuster.git
cd BackdoorBuster
chmod +x install_kali_simple.sh && ./install_kali_simple.sh
```

**Universal (Python):**
```bash
git clone https://github.com/Qixpy/BackdoorBuster.git
cd BackdoorBuster
python install.py
```

### Usage

**Command Line Interface:**
```bash
# Basic usage
python main.py

# Show version
python main.py --version

# Scan a single directory
python main.py --scan /path/to/directory

# Scan multiple directories (NEW!)
python main.py --scan /etc /usr/bin /bin /var/log /tmp

# Scan with home directory expansion
python main.py --scan ~/.config ~/.ssh ~/.local/bin

# Start web interface
python main.py --web-server
```

## 📁 Log Files Location

### **Default Log Directory:**
```bash
./logs/                    # Main log directory
├── *.json                # Scan results (JSON format)
├── *.html                # Simple scan reports (basic HTML)
└── backdoorbuster.log    # Application logs
```

### **Two Types of Reports:**

**1. 📊 Web Dashboard (Advanced Interface):**
- Access via: `python3 main.py --web-server`
- Features: Interactive tables, real-time data, advanced styling
- URL: http://127.0.0.1:5000
- Uses `templates/log.html` template

**2. 📄 Standalone HTML Reports (Simple):**
- Generated automatically during scans
- Files: `scan_report_*.html` in logs directory
- Features: Basic styling, static content, printable format
- Purpose: Quick viewing, sharing, archiving

Both reports show the same scan data but in different formats.

### **Find Your Logs:**
```bash
# List available logs
python3 main.py --logs

# Check logs directory
ls -la logs/

# Search for log files
find . -name "*.log" -o -name "*.json" -o -name "*.html"

# View logs in web browser
python3 main.py --web-server
```

### **Kali Linux Log Locations:**
```bash
~/BackdoorBuster/logs/           # Primary location
~/BackdoorBuster/*.json          # Scan results
~/BackdoorBuster/*.html          # HTML reports
```

**Using Launchers (after installation):**
```bash
# Windows
backdoorbuster.bat
backdoorbuster-web.bat

# macOS/Linux
./backdoorbuster.sh
./backdoorbuster-web.sh
```

## Requirements

### Core Dependencies (Minimal Installation)
- Python 3.8+
- Flask (web interface)
- Jinja2 (templating)
- termcolor (colored output)

### Optional Dependencies (Full Features)
- psycopg2-binary (database support)
- cryptography (encryption features)
- yara-python (YARA rules)
- psutil (system monitoring)
- scapy (network analysis)
- reportlab (PDF reports)

## Architecture

BackdoorBuster uses a modular architecture with graceful degradation:

- **Core Engine**: Basic scanning and analysis
- **Web Interface**: Flask-based dashboard for log viewing
- **Database Layer**: Optional PostgreSQL integration
- **Rule Engine**: Optional YARA rules for custom detection
- **Monitoring**: Real-time system monitoring
- **Reporting**: Multiple export formats

## Configuration

Edit `config.json` to customize:

```json
{
    "scan_paths": ["/path/to/scan"],
    "output_dir": "./logs",
    "web_server": {
        "host": "127.0.0.1",
        "port": 5000
    },
    "encryption": {
        "enabled": false
    }
}
```

## Troubleshooting

### Kali Linux Issues

If installation fails on Kali Linux, try these solutions:

**Run Diagnostics:**
```bash
chmod +x diagnose_kali.sh && ./diagnose_kali.sh
```

**Use Simple Installer:**
```bash
chmod +x install_kali_simple.sh && ./install_kali_simple.sh
```

**Manual Installation:**
```bash
# Install system dependencies
sudo apt update
sudo apt install python3 python3-pip python3-flask python3-jinja2

# Install Python packages
pip3 install --user Flask Jinja2 termcolor psutil

# Test installation
python3 main.py --help
```

### Common Issues

- **Permission Errors**: Try installing packages with `--user` flag
- **Import Errors**: Ensure Flask and Jinja2 are installed
- **Virtual Environment Issues**: Use the simple installer instead
- **Missing Dependencies**: Install with `pip3 install --user [package]`
- **Web Server Won't Start**: Install Flask and Jinja2: `pip3 install --user Flask Jinja2`
- **Empty Log Files**: Update to latest version with `git pull origin main`
- **No Scan Results**: Logs are created in `./logs/` directory after scanning

### **🐧 Kali Linux Web Server Issues**

If you get "Internal Error" on Kali Linux when starting the web server:

**Quick Diagnostic:**
```bash
chmod +x diagnose_web_kali.sh && ./diagnose_web_kali.sh
```

**Common Kali Linux Issues:**

1. **Missing Dependencies:**
```bash
# Install Flask and Jinja2
pip3 install --user Flask Jinja2

# Alternative: system packages
sudo apt install python3-flask python3-jinja2
```

2. **No Scan Data:**
```bash
# Run a scan first to generate data
python3 main.py --scan /tmp
python3 main.py --scan /etc /usr/bin

# Then start web server
python3 main.py --web
```

3. **Template Path Issues:**
```bash
# Check templates exist
ls -la templates/log.html

# Fix permissions if needed
chmod 644 templates/log.html
```

4. **Python Path Issues:**
```bash
# Use full path if needed
cd ~/BackdoorBuster
python3 $(pwd)/main.py --web
```

5. **Port Already in Use:**
```bash
# Use different port
python3 main.py --web --port 8080
```

**Kali Debug Mode:**
```bash
# Start with verbose output
python3 main.py --web 2>&1 | tee web_debug.log
```

**Web Server Troubleshooting:**
- **"TypeError: '>=' not supported"**: Update to latest version with `git pull origin main`
- **Empty Dashboard**: Run a scan first with `--scan` to generate data
- **Flask Import Error**: Install Flask: `pip3 install --user Flask`
- **Template Not Found**: Check `templates/log.html` exists
- **No Scan Data**: Web dashboard loads the latest JSON scan file automatically

**Web Dashboard vs HTML Reports:**
- Web Dashboard: Interactive interface at http://127.0.0.1:5000
- HTML Reports: Simple static files in `logs/scan_report_*.html`
- Both show same data in different formats (this is normal!)

## Documentation

- **[Installation Guide](INSTALLATION_GUIDE.md)** - Detailed setup instructions
- **[Usage Guide](USAGE_GUIDE.md)** - Command reference and examples
- **[Quick Install](INSTALL.md)** - One-page installation reference

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Support

- **Website**: [https://shieldpy.com](https://shieldpy.com)
- **Issues**: [GitHub Issues](https://github.com/Qixpy/BackdoorBuster/issues)
- **Enterprise Support**: Contact us through our website

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security Notice

BackdoorBuster is designed for legitimate cybersecurity research and system administration. Users are responsible for ensuring they have proper authorization before scanning systems they do not own.

## Acknowledgments

- Built with modern Python security libraries
- Inspired by industry-standard malware analysis tools
- Community-driven development approach

---

**Created by Shieldpy - Professional Cybersecurity Solutions**  
*Website: https://shieldpy.com | GitHub: https://github.com/Qixpy*
