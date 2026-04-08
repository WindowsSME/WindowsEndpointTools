<#
.SYNOPSIS
    Palo Alto GlobalProtect Version Rollback & Configuration Preservation.

.DESCRIPTION
    This script automates the downgrade of GlobalProtect from version 6.3.3 to 6.2.5.
    To prevent user friction, it performs a pre-uninstallation backup of:
    1. HKLM Registry (Machine-wide portal settings)
    2. HKCU Registry (User-specific portal history)
    3. Local Data Cache (*.dat files)
    
    After installing the target MSI, it restores these settings and restarts the PanGPS service.

.PARAMETER TargetMsiName
    Defined in the Configuration section. Ensure the MSI filename matches your local source.

.NOTES
    Author:         James Romeo Gaspar
    Date:           April 8, 2026
    Target OS:      Windows 10/11 x64
    Exit Codes:     Returns MSI Exit Code on failure, or 1 if the MSI is missing.

#>

$ScriptDir = if ($PSScriptRoot) { 
    $PSScriptRoot 
} elseif ($MyInvocation.MyCommand.Path) { 
    Split-Path -Parent $MyInvocation.MyCommand.Path 
} else { 
    (Get-Location).Path
}

$TargetMsiName = "GlobalProtect64-6.2.5-c788.msi"
$MsiPath       = Join-Path $ScriptDir $TargetMsiName
$BackupFolder  = Join-Path $ScriptDir "GP_Rollback_Backup"
$LogFile       = Join-Path $ScriptDir "Rollback_Log.txt"
$HklmRegFile   = Join-Path $BackupFolder "GP_Machine.reg"
$HkcuRegFile   = Join-Path $BackupFolder "GP_User.reg"
$DataCache     = Join-Path $BackupFolder "DataCache"

function Write-Log($Message) {
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$TimeStamp : $Message" | Out-File -FilePath $LogFile -Append
    Write-Host $Message
}

if (Test-Path $BackupFolder) { Remove-Item $BackupFolder -Recurse -Force }
New-Item -Path $DataCache -ItemType Directory -Force | Out-Null

Write-Log "--- Starting GlobalProtect Rollback ---"

Write-Log "Backing up Registry Hives (Machine and User)..."

if (Test-Path "HKLM:\SOFTWARE\Palo Alto Networks\GlobalProtect") {
    Start-Process "reg.exe" -ArgumentList "export `"HKEY_LOCAL_MACHINE\SOFTWARE\Palo Alto Networks\GlobalProtect`" `"$HklmRegFile`" /y" -Wait -WindowStyle Hidden
}

if (Test-Path "HKCU:\Software\Palo Alto Networks\GlobalProtect") {
    Start-Process "reg.exe" -ArgumentList "export `"HKEY_CURRENT_USER\Software\Palo Alto Networks\GlobalProtect`" `"$HkcuRegFile`" /y" -Wait -WindowStyle Hidden
}

$InstallDir = "C:\Program Files\Palo Alto Networks\GlobalProtect"
if (Test-Path $InstallDir) {
    Write-Log "Backing up data cache (.dat files)..."
    Copy-Item -Path "$InstallDir\*.dat" -Destination $DataCache -ErrorAction SilentlyContinue
}

Write-Log "Searching for 6.3.3 to uninstall..."
$CurrentApp = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
               Where-Object { $_.DisplayName -like "*GlobalProtect*" }

if ($CurrentApp) {
    Write-Log "Uninstalling: $($CurrentApp.DisplayName) ($($CurrentApp.DisplayVersion))"
    Start-Process "msiexec.exe" -ArgumentList "/x $($CurrentApp.PSChildName) /qn /norestart" -Wait
}

if (Test-Path $MsiPath) {
    Write-Log "Installing: 6.2.5 from $MsiPath"
    $Install = Start-Process "msiexec.exe" -ArgumentList "/i `"$MsiPath`" /qn /norestart" -Wait -PassThru
    if ($Install.ExitCode -ne 0 -and $Install.ExitCode -ne 3010) {
        Write-Log "CRITICAL: Installation failed with code $($Install.ExitCode)"
        exit $Install.ExitCode
    }
} else {
    Write-Log "ERROR: MSI not found at $MsiPath"
    exit 1
}

Write-Log "Restoring settings. Stopping service for clean injection..."
Stop-Service "PanGPS" -Force -ErrorAction SilentlyContinue

if (Test-Path $HklmRegFile) { 
    Write-Log "Restoring HKLM Portals..."
    Start-Process "reg.exe" -ArgumentList "import `"$HklmRegFile`"" -Wait -WindowStyle Hidden 
}
if (Test-Path $HkcuRegFile) { 
    Write-Log "Restoring HKCU Portals..."
    Start-Process "reg.exe" -ArgumentList "import `"$HkcuRegFile`"" -Wait -WindowStyle Hidden 
}

if (Test-Path $DataCache) {
    Write-Log "Restoring data cache files..."
    Copy-Item -Path "$DataCache\*" -Destination $InstallDir -Force -ErrorAction SilentlyContinue
}

Write-Log "Restarting GlobalProtect Service..."
Start-Service "PanGPS" -ErrorAction SilentlyContinue

Write-Log "Rollback Complete. Logs and backups kept in $ScriptDir"
