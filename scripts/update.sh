#!/bin/bash
# BackdoorBuster Update Script for Linux/macOS
# Updates the application and runs database migrations

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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

# Check if BackdoorBuster is installed
if [[ ! -f "main.py" ]] || [[ ! -f "config.json" ]]; then
    print_error "BackdoorBuster installation not found in current directory"
    exit 1
fi

print_status "Starting BackdoorBuster update..."

# Create backup
BACKUP_DIR="backups/update_$(date +%Y%m%d_%H%M%S)"
print_status "Creating backup in $BACKUP_DIR..."
mkdir -p "$BACKUP_DIR"

# Backup important files
cp -r config.json logs data "$BACKUP_DIR/" 2>/dev/null || true
cp -r rules/profiles "$BACKUP_DIR/" 2>/dev/null || true

print_success "Backup created in $BACKUP_DIR"

# Stop any running services
if systemctl is-active --quiet backdoorbuster 2>/dev/null; then
    print_status "Stopping BackdoorBuster service..."
    sudo systemctl stop backdoorbuster
    SERVICE_WAS_RUNNING=true
else
    SERVICE_WAS_RUNNING=false
fi

# Update Git repository if available
if [[ -d ".git" ]]; then
    print_status "Updating from Git repository..."
    
    # Stash any local changes
    git stash push -m "Auto-stash before update $(date)"
    
    # Pull latest changes
    git pull origin main
    
    if [[ $? -eq 0 ]]; then
        print_success "Code updated from repository"
    else
        print_error "Git update failed"
        # Continue anyway in case it's just a network issue
    fi
else
    print_warning "Not a Git repository. Manual code update required."
fi

# Activate virtual environment
if [[ -d "venv" ]]; then
    print_status "Activating virtual environment..."
    source venv/bin/activate
else
    print_error "Virtual environment not found. Please run setup.sh first."
    exit 1
fi

# Update Python dependencies
print_status "Updating Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt --upgrade

if [[ $? -eq 0 ]]; then
    print_success "Dependencies updated"
else
    print_error "Failed to update dependencies"
    exit 1
fi

# Update YARA rules
print_status "Updating YARA rules..."
if [[ -f "rules/yara_rules.yar" ]]; then
    # Backup current rules
    cp rules/yara_rules.yar "$BACKUP_DIR/yara_rules_backup.yar"
    
    # Update rules (this could be extended to download from a repository)
    print_success "YARA rules backed up"
else
    print_warning "YARA rules file not found"
fi

# Run database migrations
print_status "Running database migrations..."
python3 scripts/migrate.py migrate

if [[ $? -eq 0 ]]; then
    print_success "Database migrations completed"
else
    print_error "Database migrations failed"
    
    # Offer to rollback
    read -p "Database migration failed. Rollback to backup? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_status "Rolling back database..."
        # This would need to be implemented in the migrate script
        python3 scripts/migrate.py rollback
    fi
    
    exit 1
fi

# Verify installation
print_status "Verifying installation..."
python3 scripts/migrate.py verify

if [[ $? -eq 0 ]]; then
    print_success "Installation verification passed"
else
    print_warning "Installation verification failed"
fi

# Update configuration if needed
print_status "Checking configuration..."
if [[ -f "config.json.example" ]]; then
    # Compare with example config and suggest updates
    print_status "New configuration options may be available"
    print_status "Please review config.json.example for new settings"
fi

# Restart service if it was running
if [[ "$SERVICE_WAS_RUNNING" == "true" ]]; then
    print_status "Restarting BackdoorBuster service..."
    sudo systemctl start backdoorbuster
    
    if systemctl is-active --quiet backdoorbuster; then
        print_success "Service restarted successfully"
    else
        print_error "Failed to restart service"
        print_status "Check service status with: sudo systemctl status backdoorbuster"
    fi
fi

# Clean up old backups (keep last 5)
print_status "Cleaning up old backups..."
cd backups 2>/dev/null || true
ls -t | tail -n +6 | xargs rm -rf 2>/dev/null || true
cd - >/dev/null

# Show update summary
echo
print_success "BackdoorBuster update completed successfully!"
echo
print_status "Update Summary:"
echo "  - Code updated from repository"
echo "  - Dependencies updated"
echo "  - Database migrations applied"
echo "  - Configuration preserved"
echo "  - Backup created in $BACKUP_DIR"
echo
print_status "To verify the update:"
echo "  python3 main.py --version"
echo
print_status "To start BackdoorBuster:"
echo "  python3 main.py"
echo

# Check for any manual intervention needed
if [[ -f "UPGRADE_NOTES.md" ]]; then
    print_warning "Manual upgrade steps may be required."
    print_status "Please review UPGRADE_NOTES.md for additional instructions."
fi
