<#
.SYNOPSIS
    Recursively searches specified directories for MSI files with names matching AirWatch-related patterns,
    extracts version information, and summarizes the number of files found per version.

.DESCRIPTION
    This script searches:
        - C:\Temp
        - C:\@GlobalProtect
        - Top-level of C:\
        - User-specific folders: Desktop, Documents, Downloads, Pictures, Videos

    It looks for Airwatch MSI filenames and variations.

    It uses Windows Installer COM interface to read the ProductVersion from each MSI file
    and outputs a list of found files along with their version.

    At the end, it prints a summary of how many files were found per version,
    e.g.: 24.10.8.0 (x3), 25.6.0.0 (x1)

.NOTES
    Author: James Romeo Gaspar
    Last Modified: July 30, 2025

#>


# Define name patterns to match
$patterns = @("airwatch", "agentairwatch", "airwatchagent")

# Function to check if filename matches any pattern
function Matches-Pattern($fileName, $patterns) {
    foreach ($pattern in $patterns) {
        if ($fileName -like "*$pattern*") {
            return $true
        }
    }
    return $false
}

# Function to extract version from MSI
function Get-MsiVersion($filePath) {
    try {
        $windowsInstaller = New-Object -ComObject WindowsInstaller.Installer
        $database = $windowsInstaller.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $null, $windowsInstaller, @($filePath, 0))
        $view = $database.GetType().InvokeMember("OpenView", "InvokeMethod", $null, $database, @("SELECT Value FROM Property WHERE Property = 'ProductVersion'"))
        $view.GetType().InvokeMember("Execute", "InvokeMethod", $null, $view, $null)
        $record = $view.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $view, $null)
        if ($record) {
            return $record.GetType().InvokeMember("StringData", "GetProperty", $null, $record, 1)
        }
    } catch {
        return $null
    }
}

# Initialize version counter
$versionCounts = @{}

# Define recursive search paths
$recursivePaths = @("C:\Temp", "C:\@GlobalProtect")

# Add user-specific folders
$usersPath = "C:\Users"
if (Test-Path $usersPath) {
    Get-ChildItem -Path $usersPath -Directory | ForEach-Object {
        $user = $_.FullName
        $recursivePaths += @(
            "$user\Desktop",
            "$user\Documents",
            "$user\Downloads",
            "$user\Pictures",
            "$user\Videos"
        )
    }
}

# Recursive search
foreach ($path in $recursivePaths) {
    if (Test-Path $path) {
        Get-ChildItem -Path $path -Recurse -File -Include *.msi -ErrorAction SilentlyContinue | Where-Object {
            Matches-Pattern $_.Name $patterns
        } | ForEach-Object {
            $rawVersion = Get-MsiVersion $_.FullName
            $version = if ([string]::IsNullOrWhiteSpace("$rawVersion")) { "Unknown" } else { "$rawVersion".Trim() }

            if (-not [string]::IsNullOrWhiteSpace($version)) {
                # Write-Output "$($_.FullName) - Version: $version"

                $current = 0
                if ($versionCounts.ContainsKey($version)) {
                    $current = [int]($versionCounts[$version] | Select-Object -First 1)
                }
                $versionCounts[$version] = $current + 1
            }
        }
    }
}

# Top-level search in C:\ only (non-recursive)
$topLevelPath = "C:\"
Get-ChildItem -Path $topLevelPath -File -Include *.msi -ErrorAction SilentlyContinue | Where-Object {
    Matches-Pattern $_.Name $patterns
} | ForEach-Object {
    $rawVersion = Get-MsiVersion $_.FullName
    $version = if ([string]::IsNullOrWhiteSpace("$rawVersion")) { "Unknown" } else { "$rawVersion".Trim() }

    if (-not [string]::IsNullOrWhiteSpace($version)) {
        # Write-Output "$($_.FullName) - Version: $version"

        $current = 0
        if ($versionCounts.ContainsKey($version)) {
            $current = [int]($versionCounts[$version] | Select-Object -First 1)
        }
        $versionCounts[$version] = $current + 1
    }
}

# Output version summary
if ($versionCounts.Count -gt 0) {
    $summary = ($versionCounts.GetEnumerator() | Sort-Object Name | ForEach-Object {
        "$($_.Key) (x$($_.Value))"
    }) -join ", "
    Write-Output "`nVersion Summary: $summary"
} else {
    Write-Output "`nNo matching MSI files found."
}
