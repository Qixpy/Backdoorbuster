# BackdoorBuster Usage Guide

## ✅ Fixed: No More Password Prompt

The application now runs without asking for a decryption password by default.

## Quick Start

### Command Line Interface
```bash
# Basic usage
python main.py

# Show version
python main.py --version

# Start web interface
python main.py --web-server

# Scan a directory
python main.py --scan /path/to/directory

# List available log files
python main.py --logs

# View a specific log file
python main.py --view-log filename.json

# Run without banner
python main.py --no-banner
```

### Using Launchers

**Windows:**
```cmd
# Command line interface
backdoorbuster.bat

# Web interface
backdoorbuster-web.bat
```

**Unix/Linux/macOS:**
```bash
# Command line interface
./backdoorbuster.sh

# Web interface  
./backdoorbuster-web.sh
```

## Configuration Changes Made

### 1. Encryption Disabled by Default
- `config.json` now has `"encryption": {"enabled": false}`
- Application asks for password only if encryption is explicitly enabled
- Password prompt can be skipped by pressing Enter

### 2. Optional Dependencies
- Database connection is optional (continues without PostgreSQL)
- YARA rules are optional (continues without yara-python)
- All features degrade gracefully when dependencies are missing

### 3. Command Line Arguments
- `--version` - Show version information
- `--web-server` - Start web interface
- `--port <number>` - Specify web server port
- `--host <address>` - Specify web server host
- `--no-banner` - Skip banner display
- `--scan <path>` - Scan specific directory
- `--logs` - List available log files
- `--view-log <filename>` - View specific log file

## Dependencies

### Core (Always Required)
- Python 3.8+
- Flask (for web interface)
- Jinja2 (for web templates)

### Optional (Graceful Fallbacks)
- termcolor (colored output)
- psycopg2-binary (database features)
- cryptography (encryption features)
- yara-python (YARA rules scanning)
- psutil (system monitoring)
- scapy (network analysis)

## Example Sessions

### Basic Command Line Usage
```
python main.py
> help
> scan C:\Users
> show threats
> exit
```

### Web Interface
```
python main.py --web-server
# Opens browser to http://localhost:5000
# View logs and analysis results in web UI
```

### Development Mode
```
python main.py --no-banner
# Skips banner, goes straight to command prompt
```

## Features Working

✅ **Interactive command line interface**
✅ **Web-based log viewer**
✅ **File and directory scanning**
✅ **Configuration management**
✅ **Cross-platform launchers**
✅ **Graceful dependency handling**
✅ **Professional branding and attribution**

## Troubleshooting

### "Module not found" errors
- Install core dependencies: `pip install flask jinja2 termcolor`
- Or use full dependencies: `pip install -r requirements.txt`

### Web interface issues
- Check if port 5000 is available
- Try different port: `python main.py --web-server --port 8080`

### Database connection errors
- These are normal if PostgreSQL isn't installed
- Application continues without database features

---

*Created by Shieldpy - Professional Cybersecurity Solutions*  
*Website: https://shieldpy.com | GitHub: https://github.com/Qixpy*
