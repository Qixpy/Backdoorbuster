# BackdoorBuster Installation Guide

*Created by Shieldpy - https://shieldpy.com | GitHub: https://github.com/Qixpy/BackdoorBuster*

This guide provides detailed installation instructions for BackdoorBuster on Windows, macOS, and Linux systems.

## Quick Start

### Prerequisites
- Python 3.8 or higher
- pip (Python package installer)
- Administrator/root privileges (recommended)

### One-Command Installation

**Universal Python Installer (Recommended):**
```bash
python install.py
```

**Platform-Specific Installers:**

**Windows (PowerShell):**
```powershell
.\install.ps1
```

**Windows (Batch):**
```cmd
install.bat
```

**Unix/Linux/macOS:**
```bash
chmod +x install.sh && ./install.sh
```

---

## Windows Installation

### Method 1: PowerShell Script (Recommended)
1. **Download BackdoorBuster** to your desired directory
2. **Right-click** on `install.ps1` and select **"Run with PowerShell"**
   - Or open PowerShell as Administrator and run: `.\install.ps1 -Admin`
3. **Follow the prompts** to complete installation

### Method 2: Batch Script
1. **Right-click** on `install.bat` and select **"Run as administrator"**
2. **Follow the prompts** to complete installation

### Method 3: Universal Python Installer
1. **Open Command Prompt or PowerShell**
2. **Navigate to BackdoorBuster directory**
3. **Run:** `python install.py`

### Windows Requirements
- **Python 3.8+** from [python.org](https://python.org)
  - ⚠️ Check "Add Python to PATH" during installation
- **PowerShell 5.0+** (included in Windows 10/11)

### Running BackdoorBuster on Windows
After installation, you can run BackdoorBuster using:
- **Double-click** `backdoorbuster.bat` for command-line interface
- **Double-click** `backdoorbuster-web.bat` for web interface
- **Command line:** `python main.py [options]`

---

## macOS Installation

### Method 1: Shell Script (Recommended)
1. **Download BackdoorBuster** to your desired directory
2. **Open Terminal** and navigate to the directory
3. **Run the installer:**
   ```bash
   chmod +x install.sh
   ./install.sh
   ```

### Method 2: Universal Python Installer
1. **Open Terminal**
2. **Navigate to BackdoorBuster directory**
3. **Run:** `python3 install.py`

### macOS Requirements
- **Python 3.8+** (install via [Homebrew](https://brew.sh) recommended):
  ```bash
  brew install python
  ```
- **Xcode Command Line Tools:**
  ```bash
  xcode-select --install
  ```

### Running BackdoorBuster on macOS
After installation, you can run BackdoorBuster using:
- **Terminal:** `./backdoorbuster.sh [options]`
- **Web interface:** `./backdoorbuster-web.sh`
- **Direct:** `python3 main.py [options]`

---

## Linux Installation

### Method 1: Shell Script (Recommended)
1. **Download BackdoorBuster** to your desired directory
2. **Open terminal** and navigate to the directory
3. **Run the installer:**
   ```bash
   chmod +x install.sh
   ./install.sh
   ```

### Method 2: Universal Python Installer
1. **Open terminal**
2. **Navigate to BackdoorBuster directory**
3. **Run:** `python3 install.py`

### Linux Requirements

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv
```

**CentOS/RHEL/Fedora:**
```bash
# CentOS/RHEL
sudo yum install python3 python3-pip

# Fedora
sudo dnf install python3 python3-pip
```

**Arch Linux:**
```bash
sudo pacman -S python python-pip
```

### Running BackdoorBuster on Linux
After installation, you can run BackdoorBuster using:
- **Terminal:** `./backdoorbuster.sh [options]`
- **Web interface:** `./backdoorbuster-web.sh`
- **Direct:** `python3 main.py [options]`

---

## Manual Installation

If the automated installers don't work for your system, you can install manually:

### 1. Install Python Dependencies
```bash
# Upgrade pip
python -m pip install --upgrade pip

# Install requirements
python -m pip install -r requirements.txt
```

### 2. Create Configuration
```bash
# Copy example configuration
cp config.json.example config.json

# Edit configuration as needed
nano config.json  # or your preferred editor
```

### 3. Create Directories
```bash
mkdir -p logs data temp
```

### 4. Test Installation
```bash
python main.py --version
```

---

## Configuration

After installation, configure BackdoorBuster by editing `config.json`:

```json
{
    "scan_paths": ["/path/to/scan"],
    "output_dir": "./logs",
    "max_file_size": 104857600,
    "scan_timeout": 300,
    "web_server": {
        "host": "127.0.0.1",
        "port": 5000,
        "debug": false
    },
    "logging": {
        "level": "INFO",
        "file": "./logs/backdoorbuster.log"
    }
}
```

### Key Configuration Options
- **scan_paths**: Directories to scan for malware
- **output_dir**: Directory for log files and reports
- **max_file_size**: Maximum file size to scan (bytes)
- **scan_timeout**: Timeout for each scan operation (seconds)
- **web_server**: Web interface settings
- **logging**: Logging configuration

---

## Usage Examples

### Command Line Interface
```bash
# Basic scan
python main.py --scan /path/to/directory

# Scan with custom output
python main.py --scan /path/to/directory --output ./custom_logs

# View logs
python main.py --logs

# View specific log
python main.py --view-log filename.json
```

### Web Interface
```bash
# Start web server
python main.py --web-server

# Then open http://localhost:5000 in your browser
```

### Using Launchers
```bash
# Windows
backdoorbuster.bat --scan C:\Users
backdoorbuster-web.bat

# Unix/Linux/macOS
./backdoorbuster.sh --scan /home
./backdoorbuster-web.sh
```

---

## Troubleshooting

### Python Not Found
- **Windows**: Reinstall Python and check "Add Python to PATH"
- **macOS**: Install via Homebrew: `brew install python`
- **Linux**: Install via package manager (see Linux Requirements above)

### Permission Errors
- **Windows**: Run installer as Administrator
- **Unix/Linux/macOS**: Use `sudo` if needed, but avoid running as root

### Dependencies Installation Failed
```bash
# Try upgrading pip first
python -m pip install --upgrade pip

# Install dependencies manually
python -m pip install flask jinja2 pathlib termcolor

# Or install with user flag
python -m pip install --user -r requirements.txt
```

### Web Interface Not Accessible
1. Check if port 5000 is available
2. Verify firewall settings
3. Try different port: `python main.py --web-server --port 8080`

### Log Viewer Issues
1. Ensure log files exist in the logs directory
2. Check file permissions
3. Verify JSON format of log files

---

## Uninstallation

To remove BackdoorBuster:

1. **Delete the installation directory**
2. **Remove any created shortcuts/launchers**
3. **Optionally remove Python dependencies:**
   ```bash
   python -m pip uninstall -r requirements.txt
   ```

---

## Support

For installation support and issues:

- **Website**: [https://shieldpy.com](https://shieldpy.com)
- **GitHub Issues**: [https://github.com/Qixpy/BackdoorBuster/issues](https://github.com/Qixpy/BackdoorBuster/issues)
- **Documentation**: Check README.md for additional information

---

## Security Considerations

- **Run with appropriate privileges**: Avoid running as root/Administrator unless necessary
- **Network access**: Web interface binds to localhost by default
- **Log files**: May contain sensitive information, secure accordingly
- **Scan paths**: Be mindful of what directories you're scanning

---

*Created by Shieldpy - Professional Cybersecurity Solutions*  
*Website: https://shieldpy.com | GitHub: https://github.com/Qixpy*
