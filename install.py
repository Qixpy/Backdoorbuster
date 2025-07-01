#!/usr/bin/env python3
"""
BackdoorBuster Universal Installer
Cross-platform installer for Windows, macOS, and Linux

Created by Shieldpy - https://shieldpy.com
GitHub: https://github.com/Qixpy/BackdoorBuster
"""

import os
import sys
import json
import platform
import subprocess
import shutil
import urllib.request
from pathlib import Path

class BackdoorBusterInstaller:
    """Universal BackdoorBuster installer"""
    
    def __init__(self):
        self.platform = platform.system().lower()
        self.architecture = platform.machine().lower()
        self.base_dir = Path(__file__).parent.absolute()
        self.python_cmd = self._get_python_command()
        
        # Color codes for terminal output
        self.colors = {
            'red': '\033[91m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'blue': '\033[94m',
            'purple': '\033[95m',
            'cyan': '\033[96m',
            'white': '\033[97m',
            'bold': '\033[1m',
            'end': '\033[0m'
        }
        
        # Disable colors on Windows unless using Windows Terminal
        if self.platform == 'windows' and 'WT_SESSION' not in os.environ:
            self.colors = {key: '' for key in self.colors}
    
    def _get_python_command(self):
        """Determine the correct Python command for this platform"""
        commands = ['python3', 'python', 'py']
        for cmd in commands:
            try:
                result = subprocess.run([cmd, '--version'], 
                                      capture_output=True, text=True)
                if result.returncode == 0 and 'Python 3.' in result.stdout:
                    return cmd
            except FileNotFoundError:
                continue
        return None
    
    def print_colored(self, text, color='white', bold=False):
        """Print colored text to terminal"""
        color_code = self.colors.get(color, self.colors['white'])
        bold_code = self.colors['bold'] if bold else ''
        end_code = self.colors['end']
        print(f"{bold_code}{color_code}{text}{end_code}")
    
    def print_banner(self):
        """Print the installation banner"""
        banner = f"""
{self.colors['cyan']}{self.colors['bold']}
╔══════════════════════════════════════════════════════════════╗
║                    BackdoorBuster Installer                 ║
║               Advanced Malware Detection Tool               ║
║                                                              ║
║              Created by Shieldpy - shieldpy.com             ║
║           GitHub: https://github.com/Qixpy/BackdoorBuster   ║
╚══════════════════════════════════════════════════════════════╝
{self.colors['end']}
"""
        print(banner)
        
        # Platform info
        self.print_colored(f"Platform: {platform.system()} {platform.release()}", 'blue')
        self.print_colored(f"Architecture: {self.architecture}", 'blue')
        self.print_colored(f"Python: {self.python_cmd}", 'blue')
        print()
    
    def check_python(self):
        """Check Python installation and version"""
        self.print_colored("Checking Python installation...", 'yellow', True)
        
        if not self.python_cmd:
            self.print_colored("❌ Python 3.8+ is required but not found!", 'red', True)
            self.print_colored("Please install Python from: https://python.org", 'yellow')
            return False
        
        try:
            result = subprocess.run([self.python_cmd, '--version'], 
                                  capture_output=True, text=True)
            version_str = result.stdout.strip().replace('Python ', '')
            version_parts = version_str.split('.')
            major, minor = int(version_parts[0]), int(version_parts[1])
            
            if major < 3 or (major == 3 and minor < 8):
                self.print_colored(f"❌ Python 3.8+ required. Found: {version_str}", 'red', True)
                return False
            
            self.print_colored(f"✅ Python {version_str} found", 'green')
            return True
            
        except Exception as e:
            self.print_colored(f"❌ Error checking Python: {e}", 'red', True)
            return False
    
    def check_pip(self):
        """Check pip installation"""
        self.print_colored("Checking pip...", 'yellow', True)
        
        try:
            result = subprocess.run([self.python_cmd, '-m', 'pip', '--version'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                self.print_colored("✅ pip is available", 'green')
                return True
            else:
                # Try to install pip if it's missing
                self.print_colored("pip not found, attempting to install...", 'yellow')
                try:
                    subprocess.run([self.python_cmd, '-m', 'ensurepip', '--upgrade'], 
                                  check=True, capture_output=True)
                    self.print_colored("✅ pip installed successfully", 'green')
                    return True
                except subprocess.CalledProcessError:
                    self.print_colored("❌ Failed to install pip", 'red', True)
                    self.print_colored("Please install pip manually", 'yellow')
                    return False
        except Exception as e:
            self.print_colored(f"❌ Error checking pip: {e}", 'red', True)
            return False
    
    def install_dependencies(self):
        """Install Python dependencies"""
        self.print_colored("Installing Python dependencies...", 'yellow', True)
        
        # Try core requirements first, fall back to full requirements
        requirements_files = ['requirements_core.txt', 'requirements.txt']
        requirements_file = None
        
        for req_file in requirements_files:
            req_path = self.base_dir / req_file
            if req_path.exists():
                requirements_file = req_path
                break
        
        if not requirements_file:
            self.print_colored("❌ No requirements file found!", 'red', True)
            return False
        
        self.print_colored(f"Using: {requirements_file.name}", 'blue')
        
        try:
            # Upgrade pip first
            subprocess.run([self.python_cmd, '-m', 'pip', 'install', '--upgrade', 'pip'], 
                          check=True, capture_output=True)
            
            # Install requirements
            subprocess.run([self.python_cmd, '-m', 'pip', 'install', '-r', str(requirements_file)], 
                          check=True, capture_output=True)
            
            self.print_colored("✅ Dependencies installed successfully", 'green')
            return True
            
        except subprocess.CalledProcessError as e:
            self.print_colored(f"❌ Failed to install dependencies: {e}", 'red', True)
            return False
    
    def create_config(self):
        """Create configuration file"""
        self.print_colored("Creating configuration...", 'yellow', True)
        
        config_file = self.base_dir / 'config.json'
        config_example = self.base_dir / 'config.json.example'
        
        # If config exists, ask before overwriting
        if config_file.exists():
            response = input("Configuration file exists. Overwrite? (y/N): ").strip().lower()
            if response != 'y':
                self.print_colored("✅ Keeping existing configuration", 'green')
                return True
        
        # Copy from example if available
        if config_example.exists():
            try:
                shutil.copy2(config_example, config_file)
                self.print_colored("✅ Configuration created from template", 'green')
                return True
            except Exception as e:
                self.print_colored(f"❌ Failed to copy config template: {e}", 'red')
        
        # Create default config
        default_config = {
            "scan_paths": ["C:\\Users" if self.platform == 'windows' else "/home"],
            "output_dir": "./logs",
            "max_file_size": 104857600,
            "scan_timeout": 300,
            "web_server": {
                "host": "127.0.0.1",
                "port": 5000,
                "debug": False
            },
            "logging": {
                "level": "INFO",
                "file": "./logs/backdoorbuster.log"
            }
        }
        
        try:
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=4)
            self.print_colored("✅ Default configuration created", 'green')
            return True
        except Exception as e:
            self.print_colored(f"❌ Failed to create config: {e}", 'red', True)
            return False
    
    def create_directories(self):
        """Create necessary directories"""
        self.print_colored("Creating directories...", 'yellow', True)
        
        directories = ['logs', 'data', 'temp']
        
        for directory in directories:
            dir_path = self.base_dir / directory
            try:
                dir_path.mkdir(exist_ok=True)
                self.print_colored(f"✅ Created/verified: {directory}/", 'green')
            except Exception as e:
                self.print_colored(f"❌ Failed to create {directory}/: {e}", 'red')
                return False
        
        return True
    
    def create_launchers(self):
        """Create platform-specific launchers"""
        self.print_colored("Creating launchers...", 'yellow', True)
        
        if self.platform == 'windows':
            self._create_windows_launchers()
        else:
            self._create_unix_launchers()
        
        return True
    
    def _create_windows_launchers(self):
        """Create Windows batch launchers"""
        # Main launcher
        launcher_content = f"""@echo off
REM BackdoorBuster Launcher
REM Created by Shieldpy - https://shieldpy.com

cd /d "%~dp0"
{self.python_cmd} main.py %*
if %ERRORLEVEL% neq 0 pause
"""
        
        launcher_path = self.base_dir / 'backdoorbuster.bat'
        with open(launcher_path, 'w') as f:
            f.write(launcher_content)
        
        # Web viewer launcher
        web_launcher_content = f"""@echo off
REM BackdoorBuster Web Viewer
REM Created by Shieldpy - https://shieldpy.com

cd /d "%~dp0"
echo Starting BackdoorBuster Web Interface...
echo Open http://localhost:5000 in your browser
echo Press Ctrl+C to stop the server
{self.python_cmd} main.py --web-server
pause
"""
        
        web_launcher_path = self.base_dir / 'backdoorbuster-web.bat'
        with open(web_launcher_path, 'w') as f:
            f.write(web_launcher_content)
        
        self.print_colored("✅ Windows launchers created", 'green')
    
    def _create_unix_launchers(self):
        """Create Unix shell launchers"""
        # Main launcher
        launcher_content = f"""#!/bin/bash
# BackdoorBuster Launcher
# Created by Shieldpy - https://shieldpy.com

cd "$(dirname "$0")"
{self.python_cmd} main.py "$@"
"""
        
        launcher_path = self.base_dir / 'backdoorbuster.sh'
        with open(launcher_path, 'w') as f:
            f.write(launcher_content)
        launcher_path.chmod(0o755)
        
        # Web viewer launcher
        web_launcher_content = f"""#!/bin/bash
# BackdoorBuster Web Viewer
# Created by Shieldpy - https://shieldpy.com

cd "$(dirname "$0")"
echo "Starting BackdoorBuster Web Interface..."
echo "Open http://localhost:5000 in your browser"
{self.python_cmd} main.py --web-server
"""
        
        web_launcher_path = self.base_dir / 'backdoorbuster-web.sh'
        with open(web_launcher_path, 'w') as f:
            f.write(web_launcher_content)
        web_launcher_path.chmod(0o755)
        
        self.print_colored("✅ Unix launchers created", 'green')
    
    def run_test(self):
        """Run a quick installation test"""
        self.print_colored("Running installation test...", 'yellow', True)
        
        try:
            # Simple test - check if main.py exists and is readable
            main_file = self.base_dir / 'main.py'
            if main_file.exists():
                self.print_colored("✅ Installation test passed", 'green')
                return True
            else:
                self.print_colored("❌ main.py not found", 'red')
                return False
        except Exception as e:
            self.print_colored(f"❌ Installation test error: {e}", 'red')
            # Don't fail installation for test errors
            self.print_colored("⚠️ Test failed but installation may still work", 'yellow')
            return True
    
    def print_completion_message(self):
        """Print installation completion message"""
        print()
        self.print_colored("🎉 Installation Complete!", 'green', True)
        print()
        self.print_colored("To use BackdoorBuster:", 'cyan', True)
        
        if self.platform == 'windows':
            self.print_colored("  • Double-click 'backdoorbuster.bat' to run", 'white')
            self.print_colored("  • Double-click 'backdoorbuster-web.bat' for web interface", 'white')
            self.print_colored(f"  • Or use: {self.python_cmd} main.py [options]", 'white')
        else:
            self.print_colored("  • Run: ./backdoorbuster.sh", 'white')
            self.print_colored("  • Web interface: ./backdoorbuster-web.sh", 'white')
            self.print_colored(f"  • Or use: {self.python_cmd} main.py [options]", 'white')
        
        print()
        self.print_colored("Documentation:", 'cyan', True)
        self.print_colored("  • README.md - Quick start guide", 'white')
        self.print_colored("  • INSTALLATION_GUIDE.md - Detailed setup", 'white')
        self.print_colored("  • config.json - Configuration settings", 'white')
        
        print()
        self.print_colored("Support:", 'cyan', True)
        self.print_colored("  • Website: https://shieldpy.com", 'white')
        self.print_colored("  • GitHub: https://github.com/Qixpy/BackdoorBuster", 'white')
        
        print()
    
    def install(self):
        """Run the complete installation process"""
        self.print_banner()
        
        steps = [
            ("Python installation", self.check_python),
            ("pip availability", self.check_pip),
            ("Python dependencies", self.install_dependencies),
            ("Configuration", self.create_config),
            ("Directories", self.create_directories),
            ("Launchers", self.create_launchers),
            ("Installation test", self.run_test)
        ]
        
        for step_name, step_func in steps:
            if not step_func():
                self.print_colored(f"❌ Installation failed at: {step_name}", 'red', True)
                return False
        
        self.print_completion_message()
        return True

def main():
    """Main installation function"""
    installer = BackdoorBusterInstaller()
    
    try:
        success = installer.install()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        installer.print_colored("\n❌ Installation cancelled by user", 'yellow', True)
        sys.exit(1)
    except Exception as e:
        installer.print_colored(f"\n❌ Unexpected error: {e}", 'red', True)
        sys.exit(1)

if __name__ == "__main__":
    main()
