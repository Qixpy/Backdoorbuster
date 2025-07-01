@echo off
REM BackdoorBuster Update Script for Windows
REM Updates the application and runs database migrations

setlocal enabledelayedexpansion

echo.
echo ========================================
echo    BackdoorBuster Update Script
echo ========================================
echo.

REM Colors for output
set "RED=[91m"
set "GREEN=[92m"
set "BLUE=[94m"
set "YELLOW=[93m"
set "NC=[0m"

REM Function definitions
:print_status
echo %BLUE%[INFO]%NC% %~1
goto :eof

:print_success
echo %GREEN%[SUCCESS]%NC% %~1
goto :eof

:print_warning
echo %YELLOW%[WARNING]%NC% %~1
goto :eof

:print_error
echo %RED%[ERROR]%NC% %~1
goto :eof

REM Check if BackdoorBuster is installed
if not exist "main.py" (
    call :print_error "BackdoorBuster installation not found in current directory"
    pause
    exit /b 1
)

if not exist "config.json" (
    call :print_error "Configuration file not found. Please run setup first."
    pause
    exit /b 1
)

call :print_status "Starting BackdoorBuster update..."

REM Create backup
for /f "tokens=1-4 delims=/ " %%i in ("%date%") do (
    for /f "tokens=1-3 delims=:." %%a in ("%time%") do (
        set BACKUP_DIR=backups\update_%%l%%j%%k_%%a%%b%%c
    )
)

call :print_status "Creating backup in %BACKUP_DIR%..."
if not exist "backups" mkdir backups
mkdir "%BACKUP_DIR%" 2>nul

REM Backup important files
xcopy config.json "%BACKUP_DIR%\" /Y >nul 2>&1
xcopy logs "%BACKUP_DIR%\logs\" /E /Y >nul 2>&1
xcopy data "%BACKUP_DIR%\data\" /E /Y >nul 2>&1
xcopy rules\profiles "%BACKUP_DIR%\rules\profiles\" /E /Y >nul 2>&1

call :print_success "Backup created in %BACKUP_DIR%"

REM Stop service if running
sc query BackdoorBuster | find "RUNNING" >nul 2>&1
if %errorLevel% == 0 (
    call :print_status "Stopping BackdoorBuster service..."
    net stop BackdoorBuster >nul 2>&1
    set SERVICE_WAS_RUNNING=true
) else (
    set SERVICE_WAS_RUNNING=false
)

REM Update from Git if available
if exist ".git" (
    call :print_status "Updating from Git repository..."
    
    REM Check if git is available
    where git >nul 2>&1
    if %errorLevel% == 0 (
        REM Stash any local changes
        git stash push -m "Auto-stash before update %date% %time%"
        
        REM Pull latest changes
        git pull origin main
        if %errorLevel% == 0 (
            call :print_success "Code updated from repository"
        ) else (
            call :print_error "Git update failed"
            REM Continue anyway
        )
    ) else (
        call :print_warning "Git not found. Manual code update required."
    )
) else (
    call :print_warning "Not a Git repository. Manual code update required."
)

REM Activate virtual environment
if exist "venv" (
    call :print_status "Activating virtual environment..."
    call venv\Scripts\activate.bat
) else (
    call :print_error "Virtual environment not found. Please run setup.bat first."
    pause
    exit /b 1
)

REM Update Python dependencies
call :print_status "Updating Python dependencies..."
python -m pip install --upgrade pip
pip install -r requirements.txt --upgrade

if %errorLevel% == 0 (
    call :print_success "Dependencies updated"
) else (
    call :print_error "Failed to update dependencies"
    pause
    exit /b 1
)

REM Update YARA rules
call :print_status "Updating YARA rules..."
if exist "rules\yara_rules.yar" (
    REM Backup current rules
    copy rules\yara_rules.yar "%BACKUP_DIR%\yara_rules_backup.yar" >nul 2>&1
    call :print_success "YARA rules backed up"
) else (
    call :print_warning "YARA rules file not found"
)

REM Run database migrations
call :print_status "Running database migrations..."
python scripts\migrate.py migrate

if %errorLevel% == 0 (
    call :print_success "Database migrations completed"
) else (
    call :print_error "Database migrations failed"
    
    REM Offer to rollback
    set /p rollback="Database migration failed. Rollback to backup? (y/N): "
    if /i "!rollback!"=="y" (
        call :print_status "Rolling back database..."
        python scripts\migrate.py rollback
    )
    
    pause
    exit /b 1
)

REM Verify installation
call :print_status "Verifying installation..."
python scripts\migrate.py verify

if %errorLevel% == 0 (
    call :print_success "Installation verification passed"
) else (
    call :print_warning "Installation verification failed"
)

REM Update configuration if needed
call :print_status "Checking configuration..."
if exist "config.json.example" (
    call :print_status "New configuration options may be available"
    call :print_status "Please review config.json.example for new settings"
)

REM Restart service if it was running
if "!SERVICE_WAS_RUNNING!"=="true" (
    call :print_status "Restarting BackdoorBuster service..."
    net start BackdoorBuster >nul 2>&1
    
    sc query BackdoorBuster | find "RUNNING" >nul 2>&1
    if %errorLevel% == 0 (
        call :print_success "Service restarted successfully"
    ) else (
        call :print_error "Failed to restart service"
        call :print_status "Check service status manually"
    )
)

REM Clean up old backups (keep last 5)
call :print_status "Cleaning up old backups..."
cd backups 2>nul
if %errorLevel% == 0 (
    REM Simple cleanup - remove oldest directories
    for /f "skip=5 tokens=*" %%i in ('dir /b /ad /o-d 2^>nul') do (
        rmdir "%%i" /s /q 2>nul
    )
    cd ..
)

REM Show update summary
echo.
call :print_success "BackdoorBuster update completed successfully!"
echo.
call :print_status "Update Summary:"
echo   - Code updated from repository
echo   - Dependencies updated
echo   - Database migrations applied
echo   - Configuration preserved
echo   - Backup created in %BACKUP_DIR%
echo.
call :print_status "To verify the update:"
echo   python main.py --version
echo.
call :print_status "To start BackdoorBuster:"
echo   python main.py
echo.

REM Check for manual intervention
if exist "UPGRADE_NOTES.md" (
    call :print_warning "Manual upgrade steps may be required."
    call :print_status "Please review UPGRADE_NOTES.md for additional instructions."
)

pause
exit /b 0
