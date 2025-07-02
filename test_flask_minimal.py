#!/usr/bin/env python3
"""
Minimal Flask test to check if web server can start
"""
import sys
import os
from pathlib import Path

# Set working directory
backdoor_dir = Path(__file__).parent
os.chdir(backdoor_dir)

print(f"Working directory: {os.getcwd()}")
print(f"Looking for scan files in: {backdoor_dir}/logs")

# Check for scan files
logs_dir = backdoor_dir / "logs"
if logs_dir.exists():
    json_files = list(logs_dir.glob('scan_*.json'))
    print(f"Found {len(json_files)} scan files: {[f.name for f in json_files]}")
else:
    print("Logs directory not found!")

# Test Flask import
try:
    from flask import Flask
    print("✅ Flask is available")
    
    # Create minimal Flask app
    app = Flask(__name__)
    
    @app.route('/')
    def test():
        return """
        <html>
        <body>
        <h1>BackdoorBuster Flask Test</h1>
        <p>Flask is working from correct directory!</p>
        <p>Working directory: {}</p>
        <p>Scan files found: {}</p>
        </body>
        </html>
        """.format(os.getcwd(), len(json_files) if 'json_files' in locals() else 0)
    
    print("🌐 Starting Flask test server...")
    print("Open http://127.0.0.1:5000 to test")
    app.run(host='127.0.0.1', port=5000, debug=False)
    
except ImportError:
    print("❌ Flask not available")
except Exception as e:
    print(f"❌ Flask test failed: {e}")
    import traceback
    traceback.print_exc()
