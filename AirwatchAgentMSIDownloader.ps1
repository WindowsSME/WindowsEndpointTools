<#
.SYNOPSIS
    Ensures that AirwatchAgent.msi in C:\Temp is current / updated.

.DESCRIPTION
    - Deletes any AirwatchAgent.msi and duplicate files older than 7 days from C:\ and C:\Temp.
    - Moves newer AirwatchAgent.msi file from C:\ to C:\Temp.(if found)
    - Checks if the MSI in C:\Temp is at least 275MB and less than 7 days old.
    - If not, downloads a fresh copy from the official Omnissa URL.
    - Retries the download once if the file is too small after initial attempt.
    - Outputs a single line summary of action/s taken.

.AUTHOR
    James Romeo Gaspar
    July 17, 2025

#>


# === Configuration ===
$searchPaths = @("C:\", "C:\Temp")
$fileName = "AirwatchAgent.msi"
$tempPath = "C:\Temp"
$downloadUrl = "https://packages.omnissa.com/wsone/AirwatchAgent.msi"
$maxAgeDays = 7
$cutoffDate = (Get-Date).AddDays(-$maxAgeDays)
$minSizeBytes = 275MB
$destinationPath = Join-Path -Path $tempPath -ChildPath $fileName

# === Action tracking ===
$deleted = $false
$moved = $false
$downloaded = $false
$downloadAttempted = $false

# === Ensure Temp directory exists ===
If (!(Test-Path -Path $tempPath)) {
    New-Item -ItemType Directory -Path $tempPath -Force | Out-Null
}

# === Clean up old files, move newer ones from C:\ to C:\Temp ===
foreach ($path in $searchPaths) {
    $files = Get-ChildItem -Path $path -Filter "AirwatchAgent*.msi" -ErrorAction SilentlyContinue
    foreach ($file in $files) {
        if ($file.LastWriteTime -lt $cutoffDate) {
            Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
            $deleted = $true
        }
        elseif ($file.DirectoryName -eq "C:\" -and $file.LastWriteTime -ge $cutoffDate) {
            Move-Item -Path $file.FullName -Destination $destinationPath -Force
            $moved = $true
        }
    }
}

# === Helper function: download the MSI ===
function Download-AirwatchAgent {
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $destinationPath -ErrorAction Stop
        return $true
    } catch {
        Write-Output "Download failed: $_"
        return $false
    }
}

# === Check if download is necessary ===
$needsDownload = $true
if (Test-Path $destinationPath) {
    $existing = Get-Item $destinationPath
    if ($existing.LastWriteTime -ge $cutoffDate -and $existing.Length -ge $minSizeBytes) {
        $needsDownload = $false
    }
}

# === Perform download if needed ===
if ($needsDownload) {
    $downloadAttempted = $true
    if (Download-AirwatchAgent) {
        $fileSize = (Get-Item $destinationPath).Length
        if ($fileSize -lt $minSizeBytes) {
            Write-Output "Downloaded file too small ($fileSize bytes). Retrying..."
            Start-Sleep -Seconds 3
            if (Download-AirwatchAgent) {
                $fileSize = (Get-Item $destinationPath).Length
                if ($fileSize -lt $minSizeBytes) {
                    Write-Output "Retry failed: Downloaded file is still too small ($fileSize bytes)."
                    $downloaded = $false
                } else {
                    $downloaded = $true
                }
            } else {
                $downloaded = $false
            }
        } else {
            $downloaded = $true
        }
    } else {
        $downloaded = $false
    }
}

# === Build and output summary ===
$summary = @()
if ($deleted)   { $summary += "Deleted old MSI" }
if ($moved)     { $summary += "Moved newer MSI to Temp" }
if ($downloaded){ $summary += "Downloaded new MSI" }

if ($summary.Count -gt 0) {
    Write-Output ($summary -join " | ")
} elseif ($downloadAttempted -and -not $downloaded) {
    Write-Output "Download failed. Please check remote machine"
} else {
    Write-Output "Updated MSI Found. No further action needed."
}
