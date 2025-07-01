@echo off
REM BackdoorBuster Windows Batch Installer
REM Created by Shieldpy - https://shieldpy.com
REM GitHub: https://github.com/Qixpy/BackdoorBuster

setlocal enabledelayedexpansion

echo.
echo ╔══════════════════════════════════════════════════════════════╗
echo ║                    BackdoorBuster Installer                 ║
echo ║               Advanced Malware Detection Tool               ║
echo ║                                                              ║
echo ║              Created by Shieldpy - shieldpy.com             ║
echo ║           GitHub: https://github.com/Qixpy/BackdoorBuster   ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.

REM Check for administrator privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [SUCCESS] Running with administrator privileges
) else (
    echo [WARNING] Running with standard user privileges
    echo [INFO] Some features may require administrator access
)

REM Check Python installation
echo [INFO] Checking Python installation...

set PYTHON_CMD=
for %%p in (python python3 py) do (
    %%p --version >nul 2>&1
    if !errorlevel! == 0 (
        for /f "tokens=2" %%v in ('%%p --version 2^>^&1') do (
            set VERSION=%%v
            echo !VERSION! | findstr /r "^3\.[89]" >nul
            if !errorlevel! == 0 (
                set PYTHON_CMD=%%p
                goto :python_found
            )
            echo !VERSION! | findstr /r "^3\.1[0-9]" >nul
            if !errorlevel! == 0 (
                set PYTHON_CMD=%%p
                goto :python_found
            )
        )
    )
)

echo [ERROR] Python 3.8+ is required but not found!
echo [INFO] Please install Python from: https://python.org
echo [INFO] Make sure to check 'Add Python to PATH' during installation
pause
exit /b 1

:python_found
echo [SUCCESS] Found Python: !PYTHON_CMD!

REM Check pip
echo [INFO] Checking pip...
!PYTHON_CMD! -m pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] pip is not available
    echo [INFO] Please reinstall Python with pip included
    pause
    exit /b 1
)
echo [SUCCESS] pip is available

REM Check requirements file
if not exist "%~dp0requirements.txt" (
    echo [ERROR] requirements.txt not found in script directory
    pause
    exit /b 1
)

REM Install dependencies
echo [INFO] Installing Python dependencies...
!PYTHON_CMD! -m pip install --upgrade pip --quiet
if %errorlevel% neq 0 (
    echo [WARNING] Failed to upgrade pip, continuing anyway...
)

!PYTHON_CMD! -m pip install -r "%~dp0requirements.txt" --quiet
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies
    pause
    exit /b 1
)
echo [SUCCESS] Dependencies installed successfully

REM Create configuration
echo [INFO] Creating configuration...
if exist "%~dp0config.json" (
    echo [WARNING] Configuration file already exists
    set /p overwrite="Overwrite existing configuration? (y/N): "
    if /i "!overwrite!" neq "y" (
        echo [SUCCESS] Keeping existing configuration
        goto :skip_config
    )
)

if exist "%~dp0config.json.example" (
    copy "%~dp0config.json.example" "%~dp0config.json" >nul
    echo [SUCCESS] Configuration created from template
) else (
    REM Create default config
    echo { > "%~dp0config.json"
    echo     "scan_paths": ["C:\\Users"], >> "%~dp0config.json"
    echo     "output_dir": "./logs", >> "%~dp0config.json"
    echo     "max_file_size": 104857600, >> "%~dp0config.json"
    echo     "scan_timeout": 300, >> "%~dp0config.json"
    echo     "web_server": { >> "%~dp0config.json"
    echo         "host": "127.0.0.1", >> "%~dp0config.json"
    echo         "port": 5000, >> "%~dp0config.json"
    echo         "debug": false >> "%~dp0config.json"
    echo     }, >> "%~dp0config.json"
    echo     "logging": { >> "%~dp0config.json"
    echo         "level": "INFO", >> "%~dp0config.json"
    echo         "file": "./logs/backdoorbuster.log" >> "%~dp0config.json"
    echo     } >> "%~dp0config.json"
    echo } >> "%~dp0config.json"
    echo [SUCCESS] Default configuration created
)

:skip_config

REM Create directories
echo [INFO] Creating directories...
for %%d in (logs data temp) do (
    if not exist "%~dp0%%d" mkdir "%~dp0%%d"
    echo [SUCCESS] Created/verified: %%d/
)

REM Create launchers
echo [INFO] Creating launchers...

REM Main launcher
echo @echo off > "%~dp0backdoorbuster.bat"
echo REM BackdoorBuster Launcher >> "%~dp0backdoorbuster.bat"
echo REM Created by Shieldpy - https://shieldpy.com >> "%~dp0backdoorbuster.bat"
echo. >> "%~dp0backdoorbuster.bat"
echo cd /d "%%~dp0" >> "%~dp0backdoorbuster.bat"
echo !PYTHON_CMD! main.py %%* >> "%~dp0backdoorbuster.bat"
echo if %%ERRORLEVEL%% neq 0 pause >> "%~dp0backdoorbuster.bat"

REM Web launcher
echo @echo off > "%~dp0backdoorbuster-web.bat"
echo REM BackdoorBuster Web Viewer >> "%~dp0backdoorbuster-web.bat"
echo REM Created by Shieldpy - https://shieldpy.com >> "%~dp0backdoorbuster-web.bat"
echo. >> "%~dp0backdoorbuster-web.bat"
echo cd /d "%%~dp0" >> "%~dp0backdoorbuster-web.bat"
echo echo Starting BackdoorBuster Web Interface... >> "%~dp0backdoorbuster-web.bat"
echo echo Open http://localhost:5000 in your browser >> "%~dp0backdoorbuster-web.bat"
echo echo Press Ctrl+C to stop the server >> "%~dp0backdoorbuster-web.bat"
echo !PYTHON_CMD! main.py --web-server >> "%~dp0backdoorbuster-web.bat"
echo pause >> "%~dp0backdoorbuster-web.bat"

echo [SUCCESS] Launchers created

REM Test installation
echo [INFO] Testing installation...
!PYTHON_CMD! "%~dp0main.py" --version >nul 2>&1
if %errorlevel% == 0 (
    echo [SUCCESS] Installation test passed
) else (
    echo [WARNING] Installation test failed, but installation may still work
)

REM Completion message
echo.
echo 🎉 Installation Complete!
echo.
echo To use BackdoorBuster:
echo   • Double-click 'backdoorbuster.bat' to run
echo   • Double-click 'backdoorbuster-web.bat' for web interface
echo   • Or use: !PYTHON_CMD! main.py [options]
echo.
echo Documentation:
echo   • README.md - Quick start guide
echo   • INSTALLATION_GUIDE.md - Detailed setup
echo   • config.json - Configuration settings
echo.
echo Support:
echo   • Website: https://shieldpy.com
echo   • GitHub: https://github.com/Qixpy/BackdoorBuster
echo.

pause
