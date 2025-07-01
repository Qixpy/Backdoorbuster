# BackdoorBuster Windows PowerShell Installer
# Created by Shieldpy - https://shieldpy.com
# GitHub: https://github.com/Qixpy/BackdoorBuster

param(
    [switch]$Admin,
    [switch]$Quiet,
    [switch]$Development
)

# Set strict mode and error action
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Banner
$banner = @"

╔══════════════════════════════════════════════════════════════╗
║                    BackdoorBuster Installer                 ║
║               Advanced Malware Detection Tool               ║
║                                                              ║
║              Created by Shieldpy - shieldpy.com             ║
║           GitHub: https://github.com/Qixpy/BackdoorBuster   ║
╚══════════════════════════════════════════════════════════════╝

"@

Write-Host $banner -ForegroundColor Cyan

# Helper functions
function Write-Status {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Error-Custom {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check admin privileges
$isAdmin = Test-Administrator
if ($isAdmin) {
    Write-Success "Running with Administrator privileges"
} else {
    Write-Warning "Running with standard user privileges"
    if ($Admin) {
        Write-Status "Restarting as Administrator..."
        Start-Process PowerShell -Verb RunAs -ArgumentList "-File `"$PSCommandPath`" -Admin"
        exit
    }
}

# Check PowerShell version
Write-Status "Checking PowerShell version..."
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Error-Custom "PowerShell 5.0+ required. Current: $($PSVersionTable.PSVersion)"
    Write-Warning "Please update PowerShell from https://github.com/PowerShell/PowerShell"
    if (-not $Quiet) { Read-Host "Press Enter to exit" }
    exit 1
}
Write-Success "PowerShell $($PSVersionTable.PSVersion) detected"

# Check Python installation
Write-Status "Checking Python installation..."
$pythonCmd = $null
$pythonCommands = @("python", "python3", "py")

foreach ($cmd in $pythonCommands) {
    try {
        $version = & $cmd --version 2>&1
        if ($LASTEXITCODE -eq 0 -and $version -match "Python 3\.(\d+)") {
            $minorVersion = [int]$matches[1]
            if ($minorVersion -ge 8) {
                $pythonCmd = $cmd
                Write-Success "Found: $version"
                break
            }
        }
    }
    catch {
        continue
    }
}

if (-not $pythonCmd) {
    Write-Error-Custom "Python 3.8+ is required but not found!"
    Write-Warning "Please install Python from: https://python.org"
    Write-Warning "Make sure to check 'Add Python to PATH' during installation"
    
    if ($isAdmin -and -not $Quiet) {
        $download = Read-Host "Open Python download page? (y/N)"
        if ($download -eq "y" -or $download -eq "Y") {
            Start-Process "https://python.org/downloads"
        }
    }
    
    if (-not $Quiet) { Read-Host "Press Enter to exit" }
    exit 1
}

# Check pip
Write-Status "Checking pip..."
try {
    & $pythonCmd -m pip --version 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Status "pip not found, attempting to install..."
        & $pythonCmd -m ensurepip --upgrade 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "pip installed successfully"
        } else {
            throw "Failed to install pip"
        }
    } else {
        Write-Success "pip is available"
    }
}
catch {
    Write-Error-Custom "pip is not available and could not be installed"
    Write-Warning "Please reinstall Python with pip included"
    if (-not $Quiet) { Read-Host "Press Enter to exit" }
    exit 1
}

# Check requirements file
$requirementsFile = Join-Path $PSScriptRoot "requirements.txt"
if (-not (Test-Path $requirementsFile)) {
    Write-Error-Custom "requirements.txt not found in script directory"
    if (-not $Quiet) { Read-Host "Press Enter to exit" }
    exit 1
}

# Install dependencies
Write-Status "Installing Python dependencies..."
try {
    # Upgrade pip first
    & $pythonCmd -m pip install --upgrade pip --quiet
    
    # Install requirements
    & $pythonCmd -m pip install -r $requirementsFile --quiet
    if ($LASTEXITCODE -ne 0) {
        throw "pip install failed"
    }
    Write-Success "Dependencies installed successfully"
}
catch {
    Write-Error-Custom "Failed to install dependencies: $_"
    if (-not $Quiet) { Read-Host "Press Enter to exit" }
    exit 1
}

# Create configuration
Write-Status "Creating configuration..."
$configFile = Join-Path $PSScriptRoot "config.json"
$configExample = Join-Path $PSScriptRoot "config.json.example"

if (Test-Path $configFile) {
    if (-not $Quiet) {
        $overwrite = Read-Host "Configuration exists. Overwrite? (y/N)"
        if ($overwrite -ne "y" -and $overwrite -ne "Y") {
            Write-Success "Keeping existing configuration"
        } else {
            Remove-Item $configFile -Force
        }
    }
}

if (-not (Test-Path $configFile)) {
    if (Test-Path $configExample) {
        Copy-Item $configExample $configFile
        Write-Success "Configuration created from template"
    } else {
        # Create default config
        $defaultConfig = @{
            scan_paths = @("C:\Users")
            output_dir = "./logs"
            max_file_size = 104857600
            scan_timeout = 300
            web_server = @{
                host = "127.0.0.1"
                port = 5000
                debug = $false
            }
            logging = @{
                level = "INFO"
                file = "./logs/backdoorbuster.log"
            }
        } | ConvertTo-Json -Depth 10
        
        $defaultConfig | Out-File -FilePath $configFile -Encoding UTF8
        Write-Success "Default configuration created"
    }
}

# Create directories
Write-Status "Creating directories..."
$directories = @("logs", "data", "temp")
foreach ($dir in $directories) {
    $dirPath = Join-Path $PSScriptRoot $dir
    if (-not (Test-Path $dirPath)) {
        New-Item -ItemType Directory -Path $dirPath -Force | Out-Null
    }
    Write-Success "Created/verified: $dir/"
}

# Create Windows launchers
Write-Status "Creating launchers..."

# Main launcher
$launcherContent = @"
@echo off
REM BackdoorBuster Launcher
REM Created by Shieldpy - https://shieldpy.com

cd /d "%~dp0"
$pythonCmd main.py %*
if %ERRORLEVEL% neq 0 pause
"@

$launcherPath = Join-Path $PSScriptRoot "backdoorbuster.bat"
$launcherContent | Out-File -FilePath $launcherPath -Encoding ASCII

# Web launcher
$webLauncherContent = @"
@echo off
REM BackdoorBuster Web Viewer
REM Created by Shieldpy - https://shieldpy.com

cd /d "%~dp0"
echo Starting BackdoorBuster Web Interface...
echo Open http://localhost:5000 in your browser
echo Press Ctrl+C to stop the server
$pythonCmd main.py --web-server
pause
"@

$webLauncherPath = Join-Path $PSScriptRoot "backdoorbuster-web.bat"
$webLauncherContent | Out-File -FilePath $webLauncherPath -Encoding ASCII

Write-Success "Launchers created"

# Test installation
Write-Status "Testing installation..."
try {
    & $pythonCmd (Join-Path $PSScriptRoot "main.py") --version 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Installation test passed"
    } else {
        Write-Warning "Installation test failed, but installation may still work"
    }
}
catch {
    Write-Warning "Could not test installation: $_"
}

# Completion message
Write-Host ""
Write-Host "🎉 Installation Complete!" -ForegroundColor Green -BackgroundColor Black
Write-Host ""
Write-Host "To use BackdoorBuster:" -ForegroundColor Cyan
Write-Host "  • Double-click 'backdoorbuster.bat' to run" -ForegroundColor White
Write-Host "  • Double-click 'backdoorbuster-web.bat' for web interface" -ForegroundColor White
Write-Host "  • Or use: $pythonCmd main.py [options]" -ForegroundColor White
Write-Host ""
Write-Host "Documentation:" -ForegroundColor Cyan
Write-Host "  • README.md - Quick start guide" -ForegroundColor White
Write-Host "  • INSTALLATION_GUIDE.md - Detailed setup" -ForegroundColor White
Write-Host "  • config.json - Configuration settings" -ForegroundColor White
Write-Host ""
Write-Host "Support:" -ForegroundColor Cyan
Write-Host "  • Website: https://shieldpy.com" -ForegroundColor White
Write-Host "  • GitHub: https://github.com/Qixpy/BackdoorBuster" -ForegroundColor White
Write-Host ""

if (-not $Quiet) {
    Read-Host "Press Enter to exit"
}
