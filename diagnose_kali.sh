#!/bin/bash
# BackdoorBuster Kali Linux Diagnostic Script
# Created by Shieldpy - https://shieldpy.com
# Run this script to diagnose installation issues on Kali Linux

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
|              BackdoorBuster Kali Diagnostics                |
|                     Troubleshooting Tool                    |
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

# Check system information
check_system() {
    echo -e "${CYAN}=== System Information ===${NC}"
    
    print_status "Operating System:"
    if [[ -f /etc/os-release ]]; then
        grep PRETTY_NAME /etc/os-release | cut -d'"' -f2
    else
        uname -a
    fi
    
    print_status "Python Version:"
    python3 --version 2>&1 || print_error "Python3 not found"
    
    print_status "Pip Version:"
    pip3 --version 2>&1 || print_error "Pip3 not found"
    
    print_status "User:"
    whoami
    
    print_status "Current Directory:"
    pwd
    
    echo
}

# Check Python environment
check_python() {
    echo -e "${CYAN}=== Python Environment ===${NC}"
    
    # Check if virtual environment exists
    if [[ -d "venv" ]]; then
        print_success "Virtual environment found"
        print_status "Activating virtual environment..."
        source venv/bin/activate
        print_status "Virtual environment Python: $(which python3)"
        print_status "Virtual environment Pip: $(which pip)"
    else
        print_warning "No virtual environment found"
        print_status "System Python: $(which python3)"
        print_status "System Pip: $(which pip3)"
    fi
    
    echo
}

# Check required files
check_files() {
    echo -e "${CYAN}=== File Check ===${NC}"
    
    required_files=("main.py" "config.json.example" "requirements_core.txt")
    
    for file in "${required_files[@]}"; do
        if [[ -f "$file" ]]; then
            print_success "Found: $file"
        else
            print_error "Missing: $file"
        fi
    done
    
    # Check directories
    required_dirs=("templates" "rules" "assets")
    
    for dir in "${required_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            print_success "Found: $dir/"
        else
            print_warning "Missing: $dir/"
        fi
    done
    
    echo
}

# Test Python imports
test_imports() {
    echo -e "${CYAN}=== Python Import Test ===${NC}"
    
    # Activate virtual environment if available
    if [[ -d "venv" ]]; then
        source venv/bin/activate
    fi
    
    # Test standard library imports
    print_status "Testing standard library imports..."
    if python3 -c "import sys, os, json, time, threading, hashlib, platform, subprocess; print('✓ Standard library OK')"; then
        print_success "Standard library imports working"
    else
        print_error "Standard library imports failed"
    fi
    
    # Test required dependencies
    deps=("flask:Flask" "jinja2:Template" "termcolor:colored")
    
    for dep in "${deps[@]}"; do
        module=$(echo $dep | cut -d: -f1)
        import_name=$(echo $dep | cut -d: -f2)
        
        print_status "Testing $module..."
        if python3 -c "from $module import $import_name; print('✓ $module available')"; then
            print_success "$module is available"
        else
            print_error "$module is not available"
        fi
    done
    
    # Test optional dependencies
    optional_deps=("psutil:Process" "cryptography.fernet:Fernet" "psycopg2:connect")
    
    for dep in "${optional_deps[@]}"; do
        module=$(echo $dep | cut -d: -f1)
        import_name=$(echo $dep | cut -d: -f2)
        
        print_status "Testing optional $module..."
        if python3 -c "from $module import $import_name; print('✓ $module available')"; then
            print_success "Optional $module is available"
        else
            print_warning "Optional $module is not available"
        fi
    done
    
    echo
}

# Test main application
test_application() {
    echo -e "${CYAN}=== Application Test ===${NC}"
    
    # Activate virtual environment if available
    if [[ -d "venv" ]]; then
        source venv/bin/activate
    fi
    
    if [[ -f "main.py" ]]; then
        print_status "Testing main application..."
        
        # Test help command
        if python3 main.py --help >/dev/null 2>&1; then
            print_success "Application help command works"
        else
            print_error "Application help command failed"
        fi
        
        # Test version command
        if python3 main.py --version >/dev/null 2>&1; then
            print_success "Application version command works"
        else
            print_warning "Application version command failed"
        fi
        
    else
        print_error "main.py not found"
    fi
    
    echo
}

# Provide recommendations
provide_recommendations() {
    echo -e "${CYAN}=== Recommendations ===${NC}"
    
    echo -e "${WHITE}If you encountered any errors, try these solutions:${NC}"
    echo
    echo -e "${YELLOW}For missing Python packages:${NC}"
    echo "  pip3 install --user Flask Jinja2 termcolor"
    echo "  or"
    echo "  python3 -m pip install Flask Jinja2 termcolor"
    echo
    echo -e "${YELLOW}For permission issues:${NC}"
    echo "  sudo apt update"
    echo "  sudo apt install python3-pip python3-venv"
    echo
    echo -e "${YELLOW}For virtual environment issues:${NC}"
    echo "  rm -rf venv"
    echo "  python3 -m venv venv"
    echo "  source venv/bin/activate"
    echo "  pip install -r requirements_core.txt"
    echo
    echo -e "${YELLOW}For Kali-specific issues:${NC}"
    echo "  sudo apt install python3-flask python3-jinja2"
    echo "  sudo apt install build-essential python3-dev"
    echo
    echo -e "${WHITE}Support: https://github.com/Qixpy/BackdoorBuster${NC}"
    echo
}

# Main diagnostic function
main() {
    print_banner
    check_system
    check_python
    check_files
    test_imports
    test_application
    provide_recommendations
}

# Run diagnostics
main "$@"
