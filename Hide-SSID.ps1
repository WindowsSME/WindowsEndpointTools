<#
.SYNOPSIS
    Manages the Windows Wi-Fi Block List (User System).

.DESCRIPTION
    This script adds or removes a defined list of SSIDs to/from the system block list.
    Blocked networks will be hidden and prevented from connecting.

.NOTES
    Author: James Romeo Gaspar
    Date: December 11, 2025
#>

# SSIDs to Hide #
$SSIDList = @(
    "SSID_Corp",
    "SSID_Guest",
    "JamesPogi"
)


function Add-BlockList {
    param (
        [string[]]$Networks
    )
    
    Write-Host "--- ADDING Networks to Block List ---" -ForegroundColor Cyan
    
    foreach ($ssid in $Networks) {
        $result = netsh wlan add filter permission=block ssid="$ssid" networktype=infrastructure 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "BLOCKED: [$ssid]" -ForegroundColor Green
        } else {
            if ($result -match "already exists") {
                Write-Host "SKIPPING: [$ssid] is already blocked." -ForegroundColor Yellow
            } else {
                Write-Host "ERROR on [$ssid]: $result" -ForegroundColor Red
            }
        }
    }
    Write-Host "-------------------------------------`n"
}

function Remove-BlockList {
    param (
        [string[]]$Networks
    )

    Write-Host "--- REMOVING Networks from Block List ---" -ForegroundColor Cyan

    foreach ($ssid in $Networks) {
        $result = netsh wlan delete filter permission=block ssid="$ssid" networktype=infrastructure 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "REMOVED: [$ssid]" -ForegroundColor Green
        } else {
            if ($result -match "is not in the system") {
                Write-Host "SKIPPING: [$ssid] was not in the block list." -ForegroundColor Yellow
            } else {
                Write-Host "ERROR on [$ssid]: $result" -ForegroundColor Red
            }
        }
    }
    Write-Host "-------------------------------------`n"
}

# --- EXECUTION --- #

# 1. Run this to BLOCK the networks in the list
Add-BlockList -Networks $SSIDList

# 2. Run this to UNBLOCK (Restore) the networks in the list
# Remove-BlockList -Networks $SSIDList

# --- VERIFICATION --- #
Write-Host "Current Filter List:" -ForegroundColor White
netsh wlan show filters
