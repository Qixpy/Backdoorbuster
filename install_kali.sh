#!/bin/bash
# BackdoorBuster Kali Linux Installation Script
# Created by Shieldpy - https://shieldpy.com
# Special handling for Kali Linux dependencies

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${CYAN}${WHITE}"
    cat << 'EOF'
+==============================================================+
|                BackdoorBuster Kali Installer                |
|            Advanced Malware Detection Tool                  |
|                                                              |
|              Created by Shieldpy - shieldpy.com             |
|           GitHub: https://github.com/Qixpy/BackdoorBuster   |
+==============================================================+
EOF
    echo -e "${NC}"
}

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running on Kali Linux
check_kali() {
    if [[ -f /etc/os-release ]]; then
        if grep -qi "kali" /etc/os-release; then
            print_success "Detected Kali Linux"
            return 0
        fi
    fi
    print_warning "This script is optimized for Kali Linux but will work on other Debian-based systems"
    return 0
}

# Install system dependencies for Kali Linux
install_system_deps() {
    print_status "Installing system dependencies..."
    
    # Update package list
    print_status "Updating package list..."
    if ! sudo apt update; then
        print_error "Failed to update package list. Check your internet connection."
        return 1
    fi
    
    # Install Python and pip if not present
    print_status "Installing Python dependencies..."
    if ! sudo apt install -y python3 python3-pip python3-venv python3-dev; then
        print_error "Failed to install Python dependencies. Trying without sudo..."
        apt install -y python3 python3-pip python3-venv python3-dev || print_warning "Some Python packages may not be installed"
    fi
    
    # Install build tools (needed for some Python packages)
    print_status "Installing build tools..."
    sudo apt install -y build-essential libssl-dev libffi-dev || print_warning "Build tools installation failed"
    
    # Install additional libraries that might be needed
    print_status "Installing additional libraries..."
    sudo apt install -y python3-flask python3-jinja2 python3-setuptools || print_warning "Some additional packages failed to install"
    
    print_success "System dependencies installation completed"
}

# Create virtual environment (recommended for Kali)
create_venv() {
    print_status "Creating Python virtual environment..."
    
    if [[ ! -d "venv" ]]; then
        if python3 -m venv venv; then
            print_success "Virtual environment created"
        else
            print_error "Failed to create virtual environment"
            print_status "Trying alternative method..."
            if sudo apt install -y python3-venv && python3 -m venv venv; then
                print_success "Virtual environment created with alternative method"
            else
                print_error "Virtual environment creation failed. Continuing without venv..."
                return 1
            fi
        fi
    else
        print_status "Virtual environment already exists"
    fi
    
    # Activate virtual environment
    if [[ -d "venv" ]]; then
        source venv/bin/activate
        print_success "Virtual environment activated"
        
        # Upgrade pip in virtual environment
        pip install --upgrade pip || print_warning "Failed to upgrade pip"
    else
        print_warning "Continuing without virtual environment"
    fi
}

# Install Python dependencies
install_python_deps() {
    print_status "Installing Python dependencies..."
    
    # Activate virtual environment if available
    if [[ -d "venv" ]]; then
        source venv/bin/activate
        print_status "Using virtual environment"
    else
        print_status "Using system Python (no virtual environment)"
    fi
    
    # Install core dependencies one by one for better error handling
    deps=("Flask>=2.0.0" "Jinja2>=3.0.0" "termcolor>=1.1.0")
    
    for dep in "${deps[@]}"; do
        print_status "Installing $dep..."
        if pip install "$dep"; then
            print_success "$dep installed successfully"
        elif pip install --user "$dep"; then
            print_success "$dep installed with --user flag"
        elif python3 -m pip install "$dep"; then
            print_success "$dep installed with python3 -m pip"
        else
            print_error "Failed to install $dep with all methods"
        fi
    done
    
    print_success "Core dependencies installation completed"
}

# Install optional dependencies
install_optional_deps() {
    print_status "Installing optional dependencies..."
    
    # Activate virtual environment if available
    if [[ -d "venv" ]]; then
        source venv/bin/activate
    fi
    
    optional_deps=("psutil>=5.8.0" "cryptography>=3.4.8")
    
    for dep in "${optional_deps[@]}"; do
        print_status "Installing optional: $dep..."
        if pip install "$dep"; then
            print_success "Optional $dep installed successfully"
        elif pip install --user "$dep"; then
            print_success "Optional $dep installed with --user flag"
        else
            print_warning "Optional $dep failed - continuing without it"
        fi
    done
}

# Create configuration
create_config() {
    print_status "Creating configuration..."
    
    if [[ -f "config.json" ]]; then
        print_warning "Configuration file already exists"
        read -p "Overwrite existing configuration? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_success "Keeping existing configuration"
            return 0
        fi
    fi
    
    if [[ -f "config.json.example" ]]; then
        cp config.json.example config.json
        print_success "Configuration created from template"
    else
        # Create default config for Kali Linux
        cat > config.json << EOF
{
    "scan_paths": ["/home", "/tmp"],
    "output_dir": "./logs",
    "max_file_size": 104857600,
    "scan_timeout": 300,
    "web_server": {
        "host": "127.0.0.1",
        "port": 5000,
        "debug": false
    },
    "encryption": {
        "enabled": false
    },
    "logging": {
        "level": "INFO",
        "file": "./logs/backdoorbuster.log"
    }
}
EOF
        print_success "Default configuration created for Kali Linux"
    fi
}

# Create directories
create_directories() {
    print_status "Creating directories..."
    
    for dir in logs data temp; do
        mkdir -p "$dir"
        print_success "Created/verified: $dir/"
    done
}

# Create Kali-specific launchers
create_launchers() {
    print_status "Creating launchers..."
    
    # Main launcher with virtual environment
    cat > backdoorbuster.sh << 'EOF'
#!/bin/bash
# BackdoorBuster Launcher for Kali Linux
# Created by Shieldpy - https://shieldpy.com

cd "$(dirname "$0")"

# Activate virtual environment if it exists
if [[ -d "venv" ]]; then
    source venv/bin/activate
fi

python3 main.py "$@"
EOF
    chmod +x backdoorbuster.sh
    
    # Web launcher with virtual environment
    cat > backdoorbuster-web.sh << 'EOF'
#!/bin/bash
# BackdoorBuster Web Viewer for Kali Linux
# Created by Shieldpy - https://shieldpy.com

cd "$(dirname "$0")"

# Activate virtual environment if it exists
if [[ -d "venv" ]]; then
    source venv/bin/activate
fi

echo "Starting BackdoorBuster Web Interface..."
echo "Open http://localhost:5000 in your browser"
echo "Press Ctrl+C to stop the server"
python3 main.py --web-server
EOF
    chmod +x backdoorbuster-web.sh
    
    print_success "Kali Linux launchers created"
}

# Test installation
test_installation() {
    print_status "Testing installation..."
    
    # Activate virtual environment for testing
    if [[ -d "venv" ]]; then
        source venv/bin/activate
        print_status "Testing with virtual environment"
    else
        print_status "Testing with system Python"
    fi
    
    # Test Python version
    python_version=$(python3 --version 2>&1)
    print_status "Python version: $python_version"
    
    # Test if main.py exists and can import required modules
    if [[ -f "main.py" ]]; then
        print_status "Testing Python imports..."
        if python3 -c "import sys, os, json, time, threading, hashlib, platform, subprocess, datetime, pathlib; print('✓ Standard library imports OK')"; then
            print_success "Standard library imports working"
        else
            print_error "Standard library imports failed"
        fi
        
        # Test Flask import
        if python3 -c "from flask import Flask; print('✓ Flask available')"; then
            print_success "Flask is available"
        else
            print_warning "Flask is not available"
        fi
        
        # Test Jinja2 import
        if python3 -c "from jinja2 import Template; print('✓ Jinja2 available')"; then
            print_success "Jinja2 is available"
        else
            print_warning "Jinja2 is not available"
        fi
        
        # Test main application
        if python3 main.py --version >/dev/null 2>&1; then
            print_success "Installation test passed"
            return 0
        else
            print_warning "Main application test failed, but core functionality may still work"
            return 0
        fi
    else
        print_error "main.py not found in current directory"
        return 1
    fi
}

# Print completion message
print_completion() {
    echo
    echo -e "${GREEN}🎉 Kali Linux Installation Complete!${NC}"
    echo
    echo -e "${CYAN}To use BackdoorBuster:${NC}"
    echo -e "${WHITE}  • Run: ./backdoorbuster.sh${NC}"
    echo -e "${WHITE}  • Web interface: ./backdoorbuster-web.sh${NC}"
    echo -e "${WHITE}  • Or use: python3 main.py [options]${NC}"
    echo
    echo -e "${CYAN}Virtual Environment:${NC}"
    if [[ -d "venv" ]]; then
        echo -e "${WHITE}  • Activate: source venv/bin/activate${NC}"
        echo -e "${WHITE}  • Deactivate: deactivate${NC}"
    else
        echo -e "${YELLOW}  • Virtual environment not created (using system Python)${NC}"
    fi
    echo
    echo -e "${CYAN}Troubleshooting:${NC}"
    echo -e "${WHITE}  • If permission errors: Try running without sudo${NC}"
    echo -e "${WHITE}  • If import errors: pip3 install --user Flask Jinja2 termcolor${NC}"
    echo -e "${WHITE}  • Update pip: python3 -m pip install --upgrade pip${NC}"
    echo -e "${WHITE}  • For YARA support: sudo apt install yara python3-yara${NC}"
    echo -e "${WHITE}  • For database support: sudo apt install postgresql python3-psycopg2${NC}"
    echo -e "${WHITE}  • Test installation: python3 main.py --help${NC}"
    echo
    echo -e "${CYAN}Support:${NC}"
    echo -e "${WHITE}  • Website: https://shieldpy.com${NC}"
    echo -e "${WHITE}  • GitHub: https://github.com/Qixpy/BackdoorBuster${NC}"
    echo
}

# Main installation function
main() {
    print_banner
    
    # Check for root (not recommended but handle gracefully)
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root. This is not recommended for security reasons."
        print_warning "Consider creating a regular user account for daily use."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_status "Installation cancelled"
            exit 0
        fi
    fi
    
    check_kali
    install_system_deps
    create_venv
    install_python_deps
    install_optional_deps
    create_config
    create_directories
    create_launchers
    test_installation
    print_completion
}

# Run main function
main "$@"
