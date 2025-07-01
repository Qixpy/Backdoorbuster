@echo off
REM BackdoorBuster Web Viewer
REM Created by Shieldpy - https://shieldpy.com

cd /d "%~dp0"
echo Starting BackdoorBuster Web Interface...
echo Open http://localhost:5000 in your browser
echo Press Ctrl+C to stop the server
python main.py --web-server
pause
