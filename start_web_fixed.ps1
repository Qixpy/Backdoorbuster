# BackdoorBuster Web Server Launcher
# PowerShell script to start web server from correct directory

Write-Host "[INFO] BackdoorBuster Web Server Launcher" -ForegroundColor Cyan
Write-Host "[INFO] Setting up environment..." -ForegroundColor Yellow

# Force change to the correct directory
$BackdoorPath = "C:\Users\suruc\OneDrive\Desktop\personal\vscode\backdoorbuster"
Set-Location -Path $BackdoorPath

Write-Host "[INFO] Current directory: $(Get-Location)" -ForegroundColor Green

# Clear any virtual environment variables
$env:VIRTUAL_ENV = $null
$env:PYTHONPATH = $null
$env:CONDA_DEFAULT_ENV = $null

# Set encoding
$env:PYTHONIOENCODING = "utf-8"

# Check for scan data
if (!(Test-Path "logs\scan_*.json")) {
    Write-Host "[ERROR] No scan data found. Please run a scan first:" -ForegroundColor Red
    Write-Host "[HELP]  python main.py --scan .\scripts" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

$scanFiles = Get-ChildItem "logs\scan_*.json"
Write-Host "[INFO] Found $($scanFiles.Count) scan files" -ForegroundColor Green

Write-Host "[INFO] Starting web server..." -ForegroundColor Yellow
Write-Host "[INFO] Open http://127.0.0.1:5000 in your browser" -ForegroundColor Cyan
Write-Host "[INFO] Press Ctrl+C to stop the server" -ForegroundColor Yellow

# Try different Python commands in order
try {
    & python main.py --web
} catch {
    try {
        & py main.py --web
    } catch {
        try {
            & py -3 main.py --web
        } catch {
            Write-Host "[ERROR] Could not start Python. Please ensure Python is installed." -ForegroundColor Red
            Read-Host "Press Enter to exit"
        }
    }
}
