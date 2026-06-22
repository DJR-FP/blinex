# Bline-X Agent Uninstaller for Windows
# Usage: Run as Administrator
#   powershell -ExecutionPolicy Bypass -File uninstall.ps1

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

function Write-Info  { Write-Host "[blinex] $args" -ForegroundColor Green }
function Write-Warn  { Write-Host "[blinex] $args" -ForegroundColor Yellow }

$ServiceName = "BlinexAgent"
$BinaryPath = "$env:ProgramFiles\Bline-X\blinex-agent.exe"
$ConfigDir = "$env:ProgramData\Bline-X"
$InstallDir = "$env:ProgramFiles\Bline-X"

# Stop and remove Windows service
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -eq "Running") {
        Write-Info "Stopping $ServiceName service..."
        Stop-Service -Name $ServiceName -Force
    }
    Write-Info "Removing $ServiceName service..."
    sc.exe delete $ServiceName | Out-Null
}

# Remove binary and install directory
if (Test-Path $InstallDir) {
    Write-Info "Removing install directory ($InstallDir)..."
    Remove-Item -Path $InstallDir -Recurse -Force
}

# Remove config and state
if (Test-Path $ConfigDir) {
    Write-Info "Removing config/state directory ($ConfigDir)..."
    Remove-Item -Path $ConfigDir -Recurse -Force
}

# Remove from PATH
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($machinePath -like "*Bline-X*") {
    Write-Info "Removing Bline-X from system PATH..."
    $newPath = ($machinePath -split ";" | Where-Object { $_ -notlike "*Bline-X*" }) -join ";"
    [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
}

# Remove firewall rules
$fwRules = Get-NetFirewallRule -DisplayName "Bline-X*" -ErrorAction SilentlyContinue
if ($fwRules) {
    Write-Info "Removing firewall rules..."
    $fwRules | Remove-NetFirewallRule
}

Write-Info "Bline-X agent uninstalled from Windows."
Write-Info "The device will remain listed in the dashboard until you remove it there."
