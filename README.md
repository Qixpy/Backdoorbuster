# BackdoorBuster

**Advanced Cross-Platform Malware Detection Tool**

*Created by [Shieldpy](https://shieldpy.com) - Professional Cybersecurity Solutions*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)](https://github.com/Qixpy/BackdoorBuster)

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

# Scan a directory
python main.py --scan /path/to/directory

# Start web interface
python main.py --web-server
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
