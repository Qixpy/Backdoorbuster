@echo off
REM BackdoorBuster Update Script for Windows
REM Created by Shieldpy - https://shieldpy.com

echo.
echo +==============================================================+
echo ^|                BackdoorBuster Update Tool                   ^|
echo ^|              Keep Your Security Tools Current               ^|
echo ^|                                                              ^|
echo ^|              Created by Shieldpy - shieldpy.com             ^|
echo +==============================================================+
echo.

echo [INFO] Checking if this is BackdoorBuster directory...
if not exist "main.py" (
    echo [ERROR] This doesn't appear to be the BackdoorBuster directory
    echo [INFO] Please run this script from the BackdoorBuster directory
    pause
    exit /b 1
)

echo [SUCCESS] BackdoorBuster directory detected
echo.

echo [INFO] Fetching latest updates from GitHub...
git pull origin main
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Git update failed
    echo [INFO] Check your internet connection or resolve conflicts
    pause
    exit /b 1
)

echo [SUCCESS] Successfully updated from Git
echo.

echo [INFO] Updating Python dependencies...
if exist "venv\" (
    echo [INFO] Using virtual environment...
    call venv\Scripts\activate.bat
    pip install --upgrade -r requirements_core.txt
) else (
    echo [INFO] Using system Python...
    pip install --user --upgrade Flask Jinja2 termcolor psutil
)

echo [SUCCESS] Dependencies updated
echo.

echo [INFO] Testing updated installation...
python main.py --version
if %ERRORLEVEL% neq 0 (
    echo [WARNING] Installation test failed, but update may still be successful
) else (
    echo [SUCCESS] Installation test passed
)

echo.
echo [SUCCESS] BackdoorBuster update completed!
echo.
echo [INFO] What's new in this version:
echo   * Enhanced multiple path scanning support
echo   * Improved cross-platform compatibility
echo   * Better error handling and diagnostics
echo   * Updated installation scripts
echo.
echo [INFO] To see all changes, check: https://github.com/Qixpy/BackdoorBuster
echo.
echo [INFO] Start using the updated version:
echo   python main.py
echo.
pause
