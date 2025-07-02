@echo off
REM BackdoorBuster Web Server Launcher
REM Forces correct working directory and environment

echo [INFO] BackdoorBuster Web Server Launcher
echo [INFO] Setting up environment...

REM Force change to the correct directory
cd /d "C:\Users\suruc\OneDrive\Desktop\personal\vscode\backdoorbuster"

REM Clear any virtual environment variables
set VIRTUAL_ENV=
set PYTHONPATH=
set CONDA_DEFAULT_ENV=

REM Set encoding
set PYTHONIOENCODING=utf-8

echo [INFO] Current directory: %CD%
echo [INFO] Checking for scan data...

if not exist "logs\scan_*.json" (
    echo [ERROR] No scan data found. Please run a scan first:
    echo [HELP]  python main.py --scan ./scripts
    pause
    exit /b 1
)

echo [INFO] Starting web server...
echo [INFO] Open http://127.0.0.1:5000 in your browser
echo [INFO] Press Ctrl+C to stop the server

REM Try different Python commands in order
python main.py --web 2>nul
if errorlevel 1 (
    py main.py --web 2>nul
    if errorlevel 1 (
        py -3 main.py --web 2>nul
        if errorlevel 1 (
            echo [ERROR] Could not start Python. Please ensure Python is installed.
            pause
        )
    )
)
