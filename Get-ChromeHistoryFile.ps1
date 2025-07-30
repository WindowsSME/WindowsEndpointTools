<#
.SYNOPSIS
    Chrome History Audit Script

.DESCRIPTION
    This PowerShell script scans all accessible user profiles on a Windows system for Google Chrome browser history files.
    It calculates the total size of history files per user and compares it against the overall profile size.
    The script logs detailed findings and exports results to CSV and log files.

.FUNCTIONS
    Convert-Size    - Converts byte values into megabytes and gigabytes.
    Log             - Writes messages to both console and log file.

.OUTPUT
    - A CSV file containing structured data about Chrome history files per user.
    - A log file summarizing system info, scan results, and export paths.

.NOTES
    Author      : James Romeo Gaspar
    Version     : 1.0
    Created     : July 23, 2025

#>

function Convert-Size {
    param([long]$bytes)
    $mb = [math]::Round($bytes / 1MB, 2)
    $gb = [math]::Round($bytes / 1GB, 2)
    return @($mb, $gb)
}

function Log {
    param([string]$msg)
    $msg | Out-File -FilePath $logPath -Append -Encoding UTF8
    Write-Host $msg
}

$usersRoot = "C:\Users"
$userFolders = Get-ChildItem $usersRoot -Directory
$results = @()
$displayTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$fileTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$exportFolder = "C:\Temp"
$hostname = $env:COMPUTERNAME
$baseName = "${hostname}_ChromeHistoryAudit_${fileTimestamp}"
$csvPath = Join-Path $exportFolder "$baseName.csv"
$logPath = Join-Path $exportFolder "$baseName.log"

if (-not (Test-Path $exportFolder)) {
    New-Item -Path $exportFolder -ItemType Directory | Out-Null
}

$serial = (Get-WmiObject -Class Win32_BIOS).SerialNumber
$diskInfo = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID = 'C:'"
$totalDisk = [math]::Round($diskInfo.Size / 1GB, 2)
$freeDisk = [math]::Round($diskInfo.FreeSpace / 1GB, 2)

$accessibleProfiles = @()
$totalProfileSizeBytes = 0

foreach ($userFolder in $userFolders) {
    try {
        $size = (Get-ChildItem $userFolder.FullName -Recurse -Force -ErrorAction Stop | Measure-Object Length -Sum).Sum
        $accessibleProfiles += $userFolder.Name
        $totalProfileSizeBytes += $size
    } catch {
        Log "Cannot access profile: $($userFolder.Name) — $($_.Exception.Message)"
    }
}

$totalProfiles = $accessibleProfiles.Count
$totalProfilesSizeGB = [math]::Round($totalProfileSizeBytes / 1GB, 2)
$totalHistoryBytes = 0
$totalHistoryMB = 0
$totalHistoryGB = 0


@"
System Info Report - Chrome History Audit
Generated: $displayTimestamp
Hostname: $hostname
Serial Number: $serial
Drive C: Total: $totalDisk GB | Free: $freeDisk GB

Profiles Scanned: $totalProfiles
Combined Profile Size: $totalProfilesSizeGB GB
--------------------------------------------------
"@ | Out-File -FilePath $logPath -Encoding UTF8

foreach ($userFolder in $userFolders) {
    $userName = $userFolder.Name
    $userPath = $userFolder.FullName

    try {
        Get-ChildItem -Path $userPath -ErrorAction Stop | Out-Null
        Log "`nChecking user: $userName"
    }
    catch {
        Log "`nCannot access user folder: $userName ($userPath)`n  Reason: $($_.Exception.Message)"
        continue
    }

    $chromeDataPath = Join-Path $userPath "AppData\Local\Google\Chrome\User Data"
    $historyFiles = @()

    if (Test-Path $chromeDataPath) {
        $profileFolders = Get-ChildItem -Path $chromeDataPath -Directory -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match '^Default$' -or $_.Name -match '^Profile \d+$'
        }

        foreach ($profile in $profileFolders) {
            $historyPath = Join-Path $profile.FullName "History"
            if (Test-Path $historyPath) {
                $file = Get-Item $historyPath
                $historyFiles += $file
                Log "  Found History: $($file.FullName)"
            } else {
                Log "  No History file in: $($profile.FullName)"
            }
        }

        if ($historyFiles.Count -eq 0) {
            Log "  No History files found in any Chrome profiles."
        }
    } else {
        Log "  No Chrome data path found for this user."
    }

    $totalHistorySizeBytes = ($historyFiles | Measure-Object -Property Length -Sum).Sum
    $userProfileSizeBytes = (Get-ChildItem $userPath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum

    $totalHistoryMB, $totalHistoryGB = Convert-Size $totalHistorySizeBytes
    $userProfileMB, $userProfileGB = Convert-Size $userProfileSizeBytes

    $percentage = if ($userProfileSizeBytes -gt 0) {
        [math]::Round(($totalHistorySizeBytes / $userProfileSizeBytes) * 100, 4)
    } else {
        0
    }

    $results += [PSCustomObject]@{
        User               = $userName
        ChromeHistoryFiles = $historyFiles.Count
        TotalHistoryMB     = $totalHistoryMB
        TotalHistoryGB     = $totalHistoryGB
        UserProfileMB      = $userProfileMB
        UserProfileGB      = $userProfileGB
        Percentage         = "$percentage`%"
    }

    Log "  ChromeHistoryFiles: $($historyFiles.Count)"
    Log "  TotalHistory: $totalHistoryMB MB ($totalHistoryGB GB)"
    Log "  UserProfile: $userProfileMB MB ($userProfileGB GB)"
    Log "  Chrome History % of Profile: $percentage%"
}

Log "`nSummary:"
$results | Format-Table -AutoSize | Out-String | Tee-Object -Variable tableOutput | Out-File -FilePath $logPath -Append -Encoding UTF8
Write-Host $tableOutput

$totalHistoryBytes = ($results | Measure-Object -Property TotalHistoryMB -Sum).Sum * 1MB
$totalHistoryMB, $totalHistoryGB = Convert-Size $totalHistoryBytes

Log "`nTotal Chrome History Size (All Users): $totalHistoryMB MB ($totalHistoryGB GB)"

$results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

Log "`nReport exported to: $csvPath"
Log "Log file saved to: $logPath"
