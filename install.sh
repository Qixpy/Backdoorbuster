#!/bin/bash
# BackdoorBuster Unix/Linux/macOS Installer
# Created by Shieldpy - https://shieldpy.com
# GitHub: https://github.com/Qixpy/BackdoorBuster

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Helper functions
print_banner() {
    echo -e "${CYAN}${WHITE}"
    cat << 'EOF'

╔══════════════════════════════════════════════════════════════╗
║                    BackdoorBuster Installer                 ║
║               Advanced Malware Detection Tool               ║
║                                                              ║
║              Created by Shieldpy - shieldpy.com             ║
║           GitHub: https://github.com/Qixpy/BackdoorBuster   ║
╚══════════════════════════════════════════════════════════════╝

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

# Detect OS and distribution
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        if command -v lsb_release >/dev/null 2>&1; then
            DISTRO=$(lsb_release -si)
        elif [[ -f /etc/os-release ]]; then
            DISTRO=$(grep '^NAME=' /etc/os-release | cut -d'"' -f2)
        else
            DISTRO="Unknown Linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        DISTRO="macOS $(sw_vers -productVersion)"
    else
        print_error "Unsupported operating system: $OSTYPE"
        exit 1
    fi
    
    print_status "Detected OS: $DISTRO"
}

# Find Python command
find_python() {
    PYTHON_CMD=""
    for cmd in python3 python py; do
        if command -v "$cmd" >/dev/null 2>&1; then
            version=$($cmd --version 2>&1)
            if [[ $version =~ Python\ 3\.([89]|[1-9][0-9]) ]]; then
                PYTHON_CMD="$cmd"
                print_success "Found: $version"
                return 0
            fi
        fi
    done
    
    print_error "Python 3.8+ is required but not found!"
    print_warning "Please install Python from: https://python.org"
    
    if [[ "$OS" == "macos" ]]; then
        print_warning "On macOS, try: brew install python"
    elif [[ "$OS" == "linux" ]]; then
        print_warning "On Ubuntu/Debian: sudo apt install python3 python3-pip"
        print_warning "On CentOS/RHEL: sudo yum install python3 python3-pip"
        print_warning "On Fedora: sudo dnf install python3 python3-pip"
    fi
    
    exit 1
}

# Check pip
check_pip() {
    print_status "Checking pip..."
    if ! $PYTHON_CMD -m pip --version >/dev/null 2>&1; then
        print_error "pip is not available"
        print_warning "Please install pip for Python 3"
        
        if [[ "$OS" == "macos" ]]; then
            print_warning "Try: $PYTHON_CMD -m ensurepip --upgrade"
        elif [[ "$OS" == "linux" ]]; then
            print_warning "On Ubuntu/Debian: sudo apt install python3-pip"
            print_warning "On CentOS/RHEL: sudo yum install python3-pip"
            print_warning "On Fedora: sudo dnf install python3-pip"
        fi
        
        exit 1
    fi
    print_success "pip is available"
}

# Install dependencies
install_dependencies() {
    print_status "Installing Python dependencies..."
    
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local requirements_file="$script_dir/requirements.txt"
    
    if [[ ! -f "$requirements_file" ]]; then
        print_error "requirements.txt not found in script directory"
        exit 1
    fi
    
    # Upgrade pip first
    if ! $PYTHON_CMD -m pip install --upgrade pip --quiet; then
        print_warning "Failed to upgrade pip, continuing anyway..."
    fi
    
    # Install requirements
    if ! $PYTHON_CMD -m pip install -r "$requirements_file" --quiet; then
        print_error "Failed to install dependencies"
        print_warning "Try installing manually: $PYTHON_CMD -m pip install -r requirements.txt"
        exit 1
    fi
    
    print_success "Dependencies installed successfully"
}

# Create configuration
create_config() {
    print_status "Creating configuration..."
    
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local config_file="$script_dir/config.json"
    local config_example="$script_dir/config.json.example"
    
    if [[ -f "$config_file" ]]; then
        print_warning "Configuration file already exists"
        read -p "Overwrite existing configuration? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_success "Keeping existing configuration"
            return 0
        fi
    fi
    
    if [[ -f "$config_example" ]]; then
        cp "$config_example" "$config_file"
        print_success "Configuration created from template"
    else
        # Create default config
        cat > "$config_file" << EOF
{
    "scan_paths": ["/home"],
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
EOF
        print_success "Default configuration created"
    fi
}

# Create directories
create_directories() {
    print_status "Creating directories..."
    
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    for dir in logs data temp; do
        local dir_path="$script_dir/$dir"
        mkdir -p "$dir_path"
        print_success "Created/verified: $dir/"
    done
}

# Create launchers
create_launchers() {
    print_status "Creating launchers..."
    
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Main launcher
    cat > "$script_dir/backdoorbuster.sh" << EOF
#!/bin/bash
# BackdoorBuster Launcher
# Created by Shieldpy - https://shieldpy.com

cd "\$(dirname "\$0")"
$PYTHON_CMD main.py "\$@"
EOF
    chmod +x "$script_dir/backdoorbuster.sh"
    
    # Web launcher
    cat > "$script_dir/backdoorbuster-web.sh" << EOF
#!/bin/bash
# BackdoorBuster Web Viewer
# Created by Shieldpy - https://shieldpy.com

cd "\$(dirname "\$0")"
echo "Starting BackdoorBuster Web Interface..."
echo "Open http://localhost:5000 in your browser"
echo "Press Ctrl+C to stop the server"
$PYTHON_CMD main.py --web-server
EOF
    chmod +x "$script_dir/backdoorbuster-web.sh"
    
    print_success "Launchers created"
}

# Test installation
test_installation() {
    print_status "Testing installation..."
    
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    if $PYTHON_CMD "$script_dir/main.py" --version >/dev/null 2>&1; then
        print_success "Installation test passed"
    else
        print_warning "Installation test failed, but installation may still work"
    fi
}

# Print completion message
print_completion() {
    echo
    echo -e "${GREEN}🎉 Installation Complete!${NC}"
    echo
    echo -e "${CYAN}To use BackdoorBuster:${NC}"
    echo -e "${WHITE}  • Run: ./backdoorbuster.sh${NC}"
    echo -e "${WHITE}  • Web interface: ./backdoorbuster-web.sh${NC}"
    echo -e "${WHITE}  • Or use: $PYTHON_CMD main.py [options]${NC}"
    echo
    echo -e "${CYAN}Documentation:${NC}"
    echo -e "${WHITE}  • README.md - Quick start guide${NC}"
    echo -e "${WHITE}  • INSTALLATION_GUIDE.md - Detailed setup${NC}"
    echo -e "${WHITE}  • config.json - Configuration settings${NC}"
    echo
    echo -e "${CYAN}Support:${NC}"
    echo -e "${WHITE}  • Website: https://shieldpy.com${NC}"
    echo -e "${WHITE}  • GitHub: https://github.com/Qixpy/BackdoorBuster${NC}"
    echo
}

# Main installation function
main() {
    print_banner
    
    # Check if running as root (not recommended)
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root is not recommended for security reasons"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_status "Installation cancelled"
            exit 0
        fi
    fi
    
    detect_os
    find_python
    check_pip
    install_dependencies
    create_config
    create_directories
    create_launchers
    test_installation
    print_completion
}

# Run main function
main "$@"
