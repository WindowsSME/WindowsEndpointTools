<#
.SYNOPSIS
    Cleans up legacy AirwatchAgent MSI installers across system and user profile folders.

.DESCRIPTION
    This script scans the following locations for AirwatchAgent MSI files:
        - C:\
        - C:\Temp
        - C:\@GlobalProtect
        - All user profile folders:
            - Downloads
            - Desktop
            - Documents

    It identifies MSI files with version ≥ 24.10, determines the latest version,
    and ensures that only one copy of the latest remains, placed at:
        C:\Temp\AirwatchAgent.msi

    All other matching files — including old versions and redundant duplicates —
    are deleted. The script supports a simulation mode for dry-run testing and
    includes retry logic when files are locked by other processes.

.PARAMETER Simulate
    Set to $true to run in Preview Mode — no files will be changed, only actions logged.

.NOTES
    Author  : James Romeo Gaspar
    Version : 1.0
    Updated : July 30, 2025

.LINK
    For troubleshooting or enhancements, contact your friendly local scripting wizard 😄
#>


$Simulate = $false

function Get-MSIProductVersion {
    param ([string]$msiPath)
    try {
        if (-not (Test-Path $msiPath)) { return $null }
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $db = $installer.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $null, $installer, @($msiPath, 0))
        $view = $db.OpenView("SELECT Value FROM Property WHERE Property = 'ProductVersion'")
        $view.Execute()
        $record = $view.Fetch()
        if ($record) { return [version]$record.StringData(1) }
    } catch { return $null }
    return $null
}

function Try-Delete {
    param (
        [string]$Path,
        [int]$MaxRetries = 3,
        [int]$DelaySeconds = 5
    )

    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            Remove-Item -Path $Path -Force -ErrorAction Stop
            # Write-Output "Deleted file: $Path (attempt $i)"
            return
        } catch {
            if ($i -eq $MaxRetries) {
                Write-Warning "FAILED to delete file after $MaxRetries attempts: $Path. $_"
            } else {
                Start-Sleep -Seconds $DelaySeconds
            }
        }
    }
}

# Define search directories
$userFolders = Get-ChildItem "C:\Users" -Directory |
    Where-Object { $_.Name -notin @("Default", "All Users", "Public") }

$profileLocations = @()

foreach ($user in $userFolders) {
    foreach ($sub in @("Downloads", "Desktop", "Documents")) {
        $folder = Join-Path $user.FullName $sub
        if (Test-Path $folder) {
            $profileLocations += $folder
        }
    }
}

$allPaths = ($dirs + $profileLocations) | Sort-Object -Unique

# Find MSI files
$msiFiles = @()
foreach ($dir in $allPaths) {
    $recurse = if ($dir -eq "C:\") { $false } else { $true }
    $files = Get-ChildItem -Path $dir -Filter "AirwatchAgent*.msi" -Recurse:$recurse -ErrorAction SilentlyContinue
    if ($files) { $msiFiles += $files }
}

# Version filtering
$minimumVersion = [version]"24.10"
$validFiles = @()

foreach ($file in $msiFiles) {
    $version = Get-MSIProductVersion -msiPath $file.FullName
    if ($version -and $version -ge $minimumVersion) {
        $validFiles += [pscustomobject]@{
            Path    = $file.FullName
            Version = $version
            Name    = $file.Name
        }
    } else {
        if ($Simulate) {
            Write-Output "Would delete old/incompatible file: $($file.FullName)"
        } else {
            Try-Delete -Path $file.FullName
        }
    }
}

if ($validFiles.Count -eq 0) {
    Write-Output "No valid MSI files found above version $minimumVersion"
    return
}

# Determine the latest valid version
$latestFile = $validFiles | Sort-Object Version -Descending | Select-Object -First 1
$targetDir = "C:\Temp"
$targetPath = Join-Path $targetDir "AirwatchAgent.msi"

# Rename if only one valid and oddly named
if ($validFiles.Count -eq 1) {
    $single = $validFiles[0]
    if ($single.Name -ne "AirwatchAgent.msi") {
        $newPath = Join-Path (Split-Path $single.Path) "AirwatchAgent.msi"
        if ($Simulate) {
            Write-Output "Would rename: $($single.Path) → $newPath"
        } else {
            try {
                Rename-Item -Path $single.Path -NewName "AirwatchAgent.msi" -Force -ErrorAction Stop
                # Write-Output "Renamed file to: $newPath"
                $single.Path = $newPath
            } catch {
                Write-Warning "FAILED to rename $($single.Path). $_"
            }
        }
    }
}

# Move/copy latest to target location
if ($latestFile.Path -ne $targetPath) {
    if ($Simulate) {
        Write-Output "Would move: $($latestFile.Path) → $targetPath"
    } else {
        try {
            if (Test-Path $targetPath) {
                Try-Delete -Path $targetPath
            }
            Copy-Item -Path $latestFile.Path -Destination $targetPath -Force -ErrorAction Stop
            # Write-Output "Copied latest MSI to: $targetPath"
            $latestFile.Path = $targetPath
        } catch {
            Write-Warning "FAILED to copy or replace target MSI. $_"
        }
    }
}

# Remove all other valid copies
foreach ($file in $validFiles) {
    if ($file.Path -ne $latestFile.Path -and $file.Path -ne $targetPath) {
        if ($Simulate) {
            Write-Output "Would delete redundant valid file: $($file.Path)"
        } else {
            Try-Delete -Path $file.Path
        }
    }
}

# Remove leftover variants in C:\Temp
Get-ChildItem -Path $targetDir -Filter "AirwatchAgent*.msi" -ErrorAction SilentlyContinue | Where-Object {
    $_.FullName -ne $targetPath
} | ForEach-Object {
    if ($Simulate) {
        Write-Output "Would remove leftover in Temp: $($_.FullName)"
    } else {
        Try-Delete -Path $_.FullName
    }
}

Write-Output "Retained latest version: $($latestFile.Version) at $targetPath"
