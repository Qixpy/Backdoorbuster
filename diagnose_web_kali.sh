#!/bin/bash

# BackdoorBuster Kali Linux Web Server Diagnostic
# Created by Shieldpy - https://shieldpy.com

echo "🔍 BackdoorBuster Kali Linux Web Server Diagnostic"
echo "=================================================="

# Check Python version
echo "🐍 Python Version:"
python3 --version
echo ""

# Check current directory
echo "📁 Current Directory:"
pwd
echo ""

# Check if main.py exists
echo "📄 Main Script:"
if [ -f "main.py" ]; then
    echo "✅ main.py found"
else
    echo "❌ main.py not found - run from BackdoorBuster directory"
fi
echo ""

# Check templates directory
echo "📁 Templates Directory:"
if [ -d "templates" ]; then
    echo "✅ templates/ directory found"
    if [ -f "templates/log.html" ]; then
        echo "✅ templates/log.html found"
    else
        echo "❌ templates/log.html missing"
    fi
else
    echo "❌ templates/ directory missing"
fi
echo ""

# Check logs directory
echo "📁 Logs Directory:"
if [ -d "logs" ]; then
    echo "✅ logs/ directory found"
    echo "📊 Log files:"
    ls -la logs/ | grep -E "\.(json|html)$" | head -5
else
    echo "❌ logs/ directory missing"
fi
echo ""

# Check Flask and Jinja2
echo "📦 Dependencies:"
python3 -c "import flask; print('✅ Flask version:', flask.__version__)" 2>/dev/null || echo "❌ Flask not installed"
python3 -c "import jinja2; print('✅ Jinja2 version:', jinja2.__version__)" 2>/dev/null || echo "❌ Jinja2 not installed"
echo ""

# Check if scan data exists
echo "📊 Scan Data:"
if [ -d "logs" ] && [ "$(ls logs/scan_*.json 2>/dev/null | wc -l)" -gt 0 ]; then
    echo "✅ Scan data found"
    latest_scan=$(ls -t logs/scan_*.json | head -1)
    echo "🕐 Latest scan: $latest_scan"
else
    echo "❌ No scan data - run: python3 main.py --scan /tmp"
fi
echo ""

# Test basic import
echo "🧪 Testing Imports:"
python3 -c "
try:
    import sys, os, json, time, threading, hashlib, secrets, platform, subprocess
    from datetime import datetime
    from pathlib import Path
    import webbrowser
    from http.server import HTTPServer, SimpleHTTPRequestHandler
    from urllib.parse import urlparse, parse_qs
    print('✅ Core imports successful')
except Exception as e:
    print('❌ Core import error:', e)
"

python3 -c "
try:
    from flask import Flask, render_template, request, jsonify
    print('✅ Flask imports successful')
except Exception as e:
    print('❌ Flask import error:', e)
"
echo ""

# Test template loading
echo "🎨 Testing Template Loading:"
if [ -f "templates/log.html" ]; then
    python3 -c "
try:
    from flask import Flask
    from pathlib import Path
    template_dir = Path('templates').resolve()
    app = Flask(__name__, template_folder=str(template_dir))
    print('✅ Template loading test passed')
except Exception as e:
    print('❌ Template loading error:', e)
"
else
    echo "❌ Cannot test - templates/log.html missing"
fi
echo ""

# Suggested fixes
echo "🔧 Suggested Fixes:"
echo "1. Install dependencies: pip3 install --user Flask Jinja2"
echo "2. Run a scan first: python3 main.py --scan /tmp"
echo "3. Check permissions: ls -la templates/"
echo "4. Update project: git pull origin main"
echo ""

echo "🌐 To start web server: python3 main.py --web"
echo "📋 For help: python3 main.py --help"
echo ""
echo "Created by Shieldpy - https://shieldpy.com"
