#!/bin/bash
# BackdoorBuster Simple Kali Linux Installation Script
# Created by Shieldpy - https://shieldpy.com
# Use this if the main install_kali.sh fails

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
|            BackdoorBuster Simple Kali Installer             |
|              No Virtual Environment Version                 |
|                                                              |
|              Created by Shieldpy - shieldpy.com             |
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

# Main installation function
main() {
    print_banner
    
    print_status "Simple installation for Kali Linux (no virtual environment)"
    echo
    
    # Update system
    print_status "Updating package list..."
    sudo apt update || print_warning "Package update failed"
    
    # Install system packages
    print_status "Installing system dependencies..."
    sudo apt install -y python3 python3-pip python3-flask python3-jinja2 python3-setuptools || print_warning "Some packages failed to install"
    
    # Install Python packages with --user flag
    print_status "Installing Python packages with --user flag..."
    pip3 install --user Flask>=2.0.0 Jinja2>=3.0.0 termcolor>=1.1.0 || print_warning "Some Python packages failed to install"
    
    # Install optional packages
    print_status "Installing optional packages..."
    pip3 install --user psutil cryptography || print_warning "Optional packages failed to install"
    
    # Create configuration
    print_status "Creating configuration..."
    if [[ -f "config.json.example" ]]; then
        cp config.json.example config.json
        print_success "Configuration created from template"
    else
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
        print_success "Default configuration created"
    fi
    
    # Create directories
    print_status "Creating directories..."
    mkdir -p logs data temp
    print_success "Directories created"
    
    # Create simple launcher
    print_status "Creating launcher..."
    cat > backdoorbuster.sh << 'EOF'
#!/bin/bash
# BackdoorBuster Simple Launcher for Kali Linux
cd "$(dirname "$0")"
python3 main.py "$@"
EOF
    chmod +x backdoorbuster.sh
    print_success "Launcher created"
    
    # Test installation
    print_status "Testing installation..."
    if python3 main.py --help >/dev/null 2>&1; then
        print_success "Installation test passed"
    else
        print_warning "Installation test failed, but may still work"
    fi
    
    # Completion message
    echo
    echo -e "${GREEN}🎉 Simple Installation Complete!${NC}"
    echo
    echo -e "${CYAN}To use BackdoorBuster:${NC}"
    echo -e "${WHITE}  • Run: ./backdoorbuster.sh${NC}"
    echo -e "${WHITE}  • Or use: python3 main.py [options]${NC}"
    echo
    echo -e "${CYAN}If you encounter import errors, try:${NC}"
    echo -e "${WHITE}  • pip3 install --user Flask Jinja2 termcolor${NC}"
    echo -e "${WHITE}  • python3 -m pip install --user Flask Jinja2 termcolor${NC}"
    echo
    echo -e "${CYAN}For diagnostics, run:${NC}"
    echo -e "${WHITE}  • ./diagnose_kali.sh${NC}"
    echo
    echo -e "${WHITE}Support: https://github.com/Qixpy/BackdoorBuster${NC}"
    echo
}

# Run main function
main "$@"
