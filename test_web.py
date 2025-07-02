import subprocess
import sys
import os

# Change to the correct directory
os.chdir(r'C:\Users\suruc\OneDrive\Desktop\personal\vscode\backdoorbuster')

# First run a scan to generate data
print("Running scan to generate test data...")
result = subprocess.run([sys.executable, 'main.py', '--scan', './scripts'], capture_output=True, text=True)
print(result.stdout)
if result.stderr:
    print("Scan errors:", result.stderr)

# Then start the web server
print("\nStarting web server...")
result = subprocess.run([sys.executable, 'main.py', '--web'], capture_output=True, text=True, timeout=10)
print(result.stdout)
if result.stderr:
    print("Web errors:", result.stderr)
