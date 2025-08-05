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
    For troubleshooting or enhancements, contact your friendly local scripting wizard - james.gaspar@taskus.com;)
#>

[CmdletBinding()]
param(
    # Enable or disable actual file operations
    [switch]   $Simulate       = $false,
    # Define the minimum acceptable MSI version
    [version]  $MinimumVersion = [version]"24.10",
    # Destination directory for the final MSI
    [string]   $TargetDir      = "C:\Temp",
    # Directories to search for AirwatchAgent MSIs
    [string[]] $SearchDirs     = @("C:\", "C:\@GlobalProtect")
)

# Store simulation flag
$script:Simulate = $Simulate

#-----------------------------------------
# Function: Get-MSIProductVersion
# Retrieves the ProductVersion property from an MSI
#-----------------------------------------
function Get-MSIProductVersion {
    param([string]$MsiPath)

    # Skip if the file does not exist
    if (-not (Test-Path $MsiPath)) { return $null }

    # Initialize COM objects
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $db = $null; $view = $null
    try {
        # Open MSI database and query ProductVersion
        $db = $installer.GetType().InvokeMember(
            "OpenDatabase", 'InvokeMethod', $null, $installer, @($MsiPath, 0)
        )
        $view = $db.OpenView("SELECT Value FROM Property WHERE Property='ProductVersion'")
        $view.Execute(); $rec = $view.Fetch()

        # Return the version if found
        if ($rec) { return [version]$rec.StringData(1) }
        return $null
    }
    catch {
        # Log failure in verbose mode
        Write-Verbose "Failed reading version from ${MsiPath}: $_"
        return $null
    }
    finally {
        # Clean up COM objects
        if ($view) { try { $view.Close() } catch {} ; [Runtime.InteropServices.Marshal]::ReleaseComObject($view) | Out-Null }
        if ($db)   { [Runtime.InteropServices.Marshal]::ReleaseComObject($db)   | Out-Null }
        [Runtime.InteropServices.Marshal]::ReleaseComObject($installer) | Out-Null
    }
}

#-----------------------------------------
# Function: Try-Rename
# Attempts to rename a file with retry logic
#-----------------------------------------
function Try-Rename {
    param(
        [string]$Path,
        [string]$NewName,
        [int]   $MaxRetries   = 3,
        [int]   $DelaySeconds = 5
    )
    # In simulate mode, just log the action
    if ($script:Simulate) { Write-Output "Would rename: '$Path' → '$NewName'"; return $true }

    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            Rename-Item -Path $Path -NewName $NewName -Force -ErrorAction Stop
            Write-Verbose "Renamed '$Path' to '$NewName'"
            return $true
        }
        catch {
            if ($i -eq $MaxRetries) { Write-Warning "Failed rename after $MaxRetries tries: $_"; return $false }
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

#-----------------------------------------
# Function: Try-Copy
# Attempts to copy a file with retry logic
#-----------------------------------------
function Try-Copy {
    param(
        [string]$SourcePath,
        [string]$DestinationPath,
        [int]   $MaxRetries   = 3,
        [int]   $DelaySeconds = 5
    )
    # In simulate mode, just log the action
    if ($script:Simulate) { Write-Output "Would copy: '$SourcePath' → '$DestinationPath'"; return $true }

    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            Copy-Item -Path $SourcePath -Destination $DestinationPath -Force -ErrorAction Stop
            Write-Verbose "Copied to '$DestinationPath'"
            return $true
        }
        catch {
            if ($i -eq $MaxRetries) { Write-Warning "Failed copy after $MaxRetries tries: $_"; return $false }
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

#-----------------------------------------
# Function: Try-Delete
# Attempts to delete a file with retry logic
#-----------------------------------------
function Try-Delete {
    param(
        [string]$Path,
        [int]   $MaxRetries   = 3,
        [int]   $DelaySeconds = 5
    )
    # In simulate mode, just log the action
    if ($script:Simulate) { Write-Output "Would delete: '$Path'"; return }

    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            Write-Verbose "Deleting '$Path' (attempt $i)"
            Remove-Item -Path $Path -Force -ErrorAction Stop
            return
        }
        catch {
            if ($i -eq $MaxRetries) { Write-Warning "Failed delete after $MaxRetries tries: $_" }
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

#-----------------------------------------
# MAIN SCRIPT FLOW
#-----------------------------------------

# 1. Collect user profile subfolders
$userFolders = Get-ChildItem 'C:\Users' -Directory |
    Where-Object Name -notin @('Default','Public','All Users','Default User')
$profileLocations = foreach ($u in $userFolders) {
    foreach ($sub in 'Downloads','Desktop','Documents','Pictures','Videos') {
        $p = Join-Path $u.FullName $sub; if (Test-Path $p) { $p }
    }
}

# 2. Combine search paths
$allPaths = ($SearchDirs + $TargetDir + $profileLocations) | Sort-Object -Unique

# 3. Find AirwatchAgent*.msi files
$msiFiles = foreach ($dir in $allPaths) {
    Get-ChildItem -Path $dir -Filter 'AirwatchAgent*.msi' -Recurse:($dir -ne 'C:\') -ErrorAction SilentlyContinue
}

# 4. Filter by version and delete older ones
$validFiles = [System.Collections.Generic.List[psobject]]::new()
foreach ($f in $msiFiles) {
    $ver = Get-MSIProductVersion -MsiPath $f.FullName
    if ($ver -and $ver -ge $MinimumVersion) { $validFiles.Add([pscustomobject]@{ Path=$f.FullName;Version=$ver }) }
    else { Try-Delete -Path $f.FullName }
}

# Stop if no valid files found
if ($validFiles.Count -eq 0) { Write-Output "No valid MSIs ≥ $MinimumVersion"; return }

# 5. Ensure target directory exists
if (-not (Test-Path $TargetDir)) {
    if ($script:Simulate) { Write-Output "Would create '$TargetDir'" }
    else { New-Item -Path $TargetDir -ItemType Directory -Force | Out-Null }
}

# 6. Pick latest MSI
$latest = $validFiles | Sort-Object Version -Descending | Select-Object -First 1
$targetPath = Join-Path $TargetDir 'AirwatchAgent.msi'

# 7. Rename single file if needed
if ($validFiles.Count -eq 1 -and ($latest.Path -notlike '*AirwatchAgent.msi')) {
    $newPath = Join-Path (Split-Path $latest.Path) 'AirwatchAgent.msi'
    Try-Rename -Path $latest.Path -NewName 'AirwatchAgent.msi' | Out-Null
    $latest.Path = $newPath
}

# 8. Copy latest to target
if ($latest.Path -ne $targetPath) {
    if (Test-Path $targetPath) { Try-Delete -Path $targetPath }
    Try-Copy -SourcePath $latest.Path -DestinationPath $targetPath | Out-Null
    # Update paths in memory
    foreach ($item in $validFiles) {
        if ($item.Path -eq $latest.Path) { $item.Path = $targetPath }
    }
}

# 9. Remove duplicates everywhere else
foreach ($item in $validFiles) {
    if ($item.Path -ne $targetPath) { Try-Delete -Path $item.Path }
}

# 10. Cleanup leftover MSIs in target directory
Get-ChildItem -Path $TargetDir -Filter 'AirwatchAgent*.msi' -ErrorAction SilentlyContinue |
    Where-Object FullName -ne $targetPath | ForEach-Object { Try-Delete -Path $_.FullName }

# Final status message
Write-Output "Retained: $($latest.Version) at $targetPath"
