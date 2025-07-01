#!/bin/bash
# BackdoorBuster Update Script
# Created by Shieldpy - https://shieldpy.com
# Automatically updates BackdoorBuster to the latest version

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
|                BackdoorBuster Update Tool                   |
|              Keep Your Security Tools Current               |
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

# Check if we're in the BackdoorBuster directory
check_directory() {
    if [[ ! -f "main.py" ]] || [[ ! -f "README.md" ]]; then
        print_error "This doesn't appear to be the BackdoorBuster directory"
        print_status "Please run this script from the BackdoorBuster directory"
        print_status "Example: cd ~/BackdoorBuster && ./update.sh"
        exit 1
    fi
    print_success "BackdoorBuster directory detected"
}

# Check current version
check_current_version() {
    print_status "Checking current version..."
    if python3 main.py --version 2>/dev/null; then
        print_success "Current installation is working"
    else
        print_warning "Current installation may have issues"
    fi
}

# Update from Git
update_from_git() {
    print_status "Fetching latest updates from GitHub..."
    
    if git pull origin main; then
        print_success "Successfully updated from Git"
    else
        print_error "Git update failed"
        print_status "You may need to resolve conflicts or check your internet connection"
        exit 1
    fi
}

# Update permissions
update_permissions() {
    print_status "Updating file permissions..."
    chmod +x *.sh 2>/dev/null || true
    chmod +x diagnose_kali.sh 2>/dev/null || true
    print_success "Permissions updated"
}

# Update Python dependencies
update_dependencies() {
    print_status "Updating Python dependencies..."
    
    # Check if virtual environment exists
    if [[ -d "venv" ]]; then
        print_status "Using virtual environment..."
        source venv/bin/activate
        
        if [[ -f "requirements_core.txt" ]]; then
            pip install --upgrade -r requirements_core.txt
        else
            pip install --upgrade Flask Jinja2 termcolor psutil
        fi
    else
        print_status "Using system Python..."
        if [[ -f "requirements_core.txt" ]]; then
            pip3 install --user --upgrade -r requirements_core.txt
        else
            pip3 install --user --upgrade Flask Jinja2 termcolor psutil
        fi
    fi
    
    print_success "Dependencies updated"
}

# Test updated installation
test_installation() {
    print_status "Testing updated installation..."
    
    # Activate virtual environment if available
    if [[ -d "venv" ]]; then
        source venv/bin/activate
    fi
    
    if python3 main.py --version >/dev/null 2>&1; then
        print_success "Installation test passed"
        python3 main.py --version
    else
        print_warning "Installation test failed, but update may still be successful"
    fi
}

# Main update function
main() {
    print_banner
    
    check_directory
    check_current_version
    
    echo
    print_status "Starting BackdoorBuster update process..."
    echo
    
    update_from_git
    update_permissions
    update_dependencies
    test_installation
    
    echo
    print_success "🎉 BackdoorBuster update completed!"
    echo
    print_status "What's new in this version:"
    echo -e "${WHITE}  • Enhanced multiple path scanning support${NC}"
    echo -e "${WHITE}  • Improved Kali Linux compatibility${NC}"
    echo -e "${WHITE}  • Better error handling and diagnostics${NC}"
    echo -e "${WHITE}  • Updated installation scripts${NC}"
    echo
    print_status "To see all changes, check: https://github.com/Qixpy/BackdoorBuster"
    echo
    print_status "Start using the updated version:"
    echo -e "${WHITE}  python3 main.py${NC}"
    echo
}

# Run update
main "$@"
