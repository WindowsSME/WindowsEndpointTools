<#
.SYNOPSIS
    Generates a report comparing total user profile size vs. Chrome browser data usage.

.DESCRIPTION
    This script scans each user profile under C:\Users, calculates the total size of the profile
    and the size of the Chrome user data folder. It then computes the percentage of profile space
    used by Chrome and exports the results to a CSV file in C:\Temp.

.NOTES
    Author: James Romeo Gaspar
    Date:   July 14, 2025
#>

# === CONFIG ===
$usersPath = "C:\Users"
$targetSubPath = "AppData\Local\Google\Chrome\User Data"
$outputFile = "C:\Temp\ChromeVsProfileUsage_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').csv"

# Ensure output directory exists
if (-not (Test-Path "C:\Temp")) {
    New-Item -ItemType Directory -Path "C:\Temp" -Force
}

# Function to get folder size in bytes
function Get-FolderSize {
    param (
        [string]$Path
    )
    if (Test-Path $Path) {
        $bytes = (Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue |
                  Measure-Object -Property Length -Sum).Sum
        return $bytes
    }
    return 0
}

# Collect results
$results = @()

Get-ChildItem -Path $usersPath -Directory | ForEach-Object {
    $username = $_.Name
    $profilePath = $_.FullName
    $chromePath = Join-Path -Path $profilePath -ChildPath $targetSubPath

    $profileBytes = Get-FolderSize -Path $profilePath
    $chromeBytes = Get-FolderSize -Path $chromePath

    $profileMB = [Math]::Round($profileBytes / 1MB, 2)
    $profileGB = [Math]::Round($profileBytes / 1GB, 2)
    $chromeMB = [Math]::Round($chromeBytes / 1MB, 2)
    $chromeGB = [Math]::Round($chromeBytes / 1GB, 2)

    if ($profileBytes -gt 0) {
        $percent = [Math]::Round(($chromeBytes / $profileBytes) * 100, 2)
    } else {
        $percent = 0
    }

    $results += [PSCustomObject]@{
        Username               = $username
        ProfilePath            = $profilePath
        ProfileSizeMB          = $profileMB
        ProfileSizeGB          = $profileGB
        ChromeDataPath         = $chromePath
        ChromeSizeMB           = $chromeMB
        ChromeSizeGB           = $chromeGB
        ChromePercentOfProfile = "$percent%"
        Timestamp              = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

# Export results to CSV
$results | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
Write-Output "Report saved to: $outputFile"
