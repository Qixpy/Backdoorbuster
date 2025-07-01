@echo off
REM BackdoorBuster Launcher
REM Created by Shieldpy - https://shieldpy.com

cd /d "%~dp0"
python main.py %*
if %ERRORLEVEL% neq 0 pause
