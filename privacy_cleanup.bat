@echo off
REM BackdoorBuster Privacy & Security Cleanup Script (Windows)
REM Created by Shieldpy - https://shieldpy.com
REM 
REM This script ensures that each BackdoorBuster installation is clean and private
REM by removing any existing scan data that might have been left behind.

echo 🔐 BackdoorBuster Privacy ^& Security Cleanup
echo ===========================================

echo 🧹 Cleaning up any existing scan data...

REM Remove all scan logs (JSON and HTML)
if exist "logs" (
    echo 📁 Found logs directory
    
    REM Count and remove JSON files
    if exist "logs\scan_*.json" (
        echo ⚠️  Found JSON scan files - removing for privacy
        del /q "logs\scan_*.json" 2>nul
    )
    
    REM Count and remove HTML files  
    if exist "logs\scan_report_*.html" (
        echo ⚠️  Found HTML scan reports - removing for privacy
        del /q "logs\scan_report_*.html" 2>nul
    )
    
    echo ✅ Removed all existing scan data
) else (
    echo ✅ No logs directory found
)

REM Remove any temporary or cache files
if exist "backdoorbuster.log" del /q "backdoorbuster.log" 2>nul
if exist ".scan_cache" del /q ".scan_cache" 2>nul
if exist "__pycache__" rmdir /s /q "__pycache__" 2>nul
if exist ".pytest_cache" rmdir /s /q ".pytest_cache" 2>nul

REM Remove any accidentally committed config files
if exist "config.json" del /q "config.json" 2>nul

REM Remove any database files that might contain scan data
if exist "warzone.db" del /q "warzone.db" 2>nul
if exist "backdoorbuster.db" del /q "backdoorbuster.db" 2>nul
if exist "data\quarantine" rmdir /s /q "data\quarantine" 2>nul
if exist "data\backups" rmdir /s /q "data\backups" 2>nul

echo.
echo 🔐 Privacy Check Complete!
echo ✅ This BackdoorBuster installation is now clean and private
echo ✅ No previous scan data remains on this system
echo ✅ Your scans will be private to this installation only
echo.
echo ℹ️  Note: Future scans will create new log files in logs/
echo ℹ️  These files are NOT shared with other users or systems
echo.
echo 🚀 Ready to use: python main.py --help
echo.
echo Created by Shieldpy - https://shieldpy.com

pause
