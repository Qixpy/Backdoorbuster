#!/bin/bash

# BackdoorBuster Privacy & Security Cleanup Script
# Created by Shieldpy - https://shieldpy.com
# 
# This script ensures that each BackdoorBuster installation is clean and private
# by removing any existing scan data that might have been left behind.

echo "🔐 BackdoorBuster Privacy & Security Cleanup"
echo "==========================================="

# Function to safely remove files
safe_remove() {
    if [ -f "$1" ]; then
        rm -f "$1"
        echo "🗑️  Removed: $1"
    fi
}

# Function to safely remove directories
safe_remove_dir() {
    if [ -d "$1" ]; then
        rm -rf "$1"
        echo "🗑️  Removed directory: $1"
    fi
}

echo "🧹 Cleaning up any existing scan data..."

# Remove all scan logs (JSON and HTML)
if [ -d "logs" ]; then
    echo "📁 Found logs directory"
    
    # Count files before cleanup
    json_count=$(find logs/ -name "scan_*.json" 2>/dev/null | wc -l)
    html_count=$(find logs/ -name "scan_report_*.html" 2>/dev/null | wc -l)
    
    if [ "$json_count" -gt 0 ] || [ "$html_count" -gt 0 ]; then
        echo "⚠️  Found $json_count JSON scan files and $html_count HTML reports"
        echo "🔒 These contain potentially sensitive scan data and will be removed"
        
        # Remove scan files
        find logs/ -name "scan_*.json" -delete 2>/dev/null
        find logs/ -name "scan_report_*.html" -delete 2>/dev/null
        
        echo "✅ Removed all existing scan data"
    else
        echo "✅ No existing scan data found"
    fi
else
    echo "✅ No logs directory found"
fi

# Remove any temporary or cache files
safe_remove "backdoorbuster.log"
safe_remove ".scan_cache"
safe_remove_dir "__pycache__"
safe_remove_dir ".pytest_cache"

# Remove any accidentally committed config files
safe_remove "config.json"

# Remove any database files that might contain scan data
safe_remove "warzone.db"
safe_remove "backdoorbuster.db"
safe_remove_dir "data/quarantine"
safe_remove_dir "data/backups"

echo ""
echo "🔐 Privacy Check Complete!"
echo "✅ This BackdoorBuster installation is now clean and private"
echo "✅ No previous scan data remains on this system"
echo "✅ Your scans will be private to this installation only"
echo ""
echo "ℹ️  Note: Future scans will create new log files in logs/"
echo "ℹ️  These files are NOT shared with other users or systems"
echo ""
echo "🚀 Ready to use: python3 main.py --help"
echo ""
echo "Created by Shieldpy - https://shieldpy.com"
