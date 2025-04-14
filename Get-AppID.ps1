function Get-AppID {

    # Get Application ID of any Installed application then copy to clipboard
    # Author: James Romeo Gaspar
    # Date: 23December2024
    # Can be used by either using
    # Get-AppID
    # or 
    # Get-AppID -ApplicationName "applicationname"
    
    param (
        [string]$ApplicationName
    )

    Write-Host ""
    if (-not $ApplicationName) {
        $ApplicationName = Read-Host "Enter the application name to search for"
    }

    Write-Host ""
    Write-Host "Searching for application..." -ForegroundColor Yellow
    Write-Host ""

    try {
        # Check using CIM/WMI
        $apps = Get-CimInstance -ClassName Win32_Product -Filter "Name LIKE '%$ApplicationName%'"

        if ($apps) {
            Write-Host "Applications found using Win32_Product:" -ForegroundColor Green
            $apps | Select-Object Name, IdentifyingNumber, Version, Vendor | Format-Table -AutoSize

            if ($apps.Count -eq 1 -or $apps -is [CimInstance]) {
                $id = $apps.IdentifyingNumber
                Write-Host "`nUninstall Key (IdentifyingNumber):" -ForegroundColor Cyan
                Write-Host $id -ForegroundColor Yellow
                Set-Clipboard -Value $id
                Write-Host "`nIdentifyingNumber has been copied to the clipboard." -ForegroundColor Green
                Write-Host "*** Press CTRL+V to paste the copied value ***`n" -ForegroundColor Green
            } else {
                Write-Host "Multiple applications found. Please refine your search for a single result to copy the IdentifyingNumber." -ForegroundColor Yellow
            }
        } else {
            Write-Host "No applications found matching '$ApplicationName'. Checking the registry..." -ForegroundColor Yellow
            
            # Define Registry Paths
            $registryPaths = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            )

            $found = $false
            $appsFromRegistry = @()

            foreach ($path in $registryPaths) {
                if (Test-Path $path) {
                    $apps = Get-ChildItem -Path $path | ForEach-Object {
                        $app = Get-ItemProperty $_.PsPath
                        if ($app.DisplayName -like "*$ApplicationName*") {
                            $appsFromRegistry += [PSCustomObject]@{
                                DisplayName     = $app.DisplayName
                                UninstallString = $app.UninstallString
                                PSPath          = $_.PsPath
                                UninstallKey    = $_.PsPath -replace "Microsoft.PowerShell.Core\\Registry::", ""
                            }
                        }
                    }
                }
            }

            if ($appsFromRegistry) {
                $found = $true
                Write-Host "`nApplications found in registry:" -ForegroundColor Green

                # Format output properly without truncation
                $appsFromRegistry | ForEach-Object {
                    Write-Host "`nDisplay Name: " -ForegroundColor Cyan -NoNewline
                    Write-Host $_.DisplayName -ForegroundColor Yellow

                    Write-Host "Uninstall String: " -ForegroundColor Cyan -NoNewline
                    Write-Host $_.UninstallString -ForegroundColor Yellow

                    Write-Host "Registry Path: " -ForegroundColor Cyan -NoNewline
                    Write-Host $_.PSPath -ForegroundColor Yellow
                }

                # If only one result, copy the uninstall key
                if ($appsFromRegistry.Count -eq 1) {
                    $uninstallKey = $appsFromRegistry[0].UninstallKey
                    Write-Host "`nUninstall Key (Registry Path):" -ForegroundColor Cyan
                    Write-Host $uninstallKey -ForegroundColor Yellow
                    Set-Clipboard -Value $uninstallKey
                    Write-Host "`nUninstall Key has been copied to the clipboard." -ForegroundColor Green
                    Write-Host "*** Press CTRL+V to paste the copied value ***`n" -ForegroundColor Green
                }
            }

            if (-not $found) {
                Write-Host "Application not found in registry either." -ForegroundColor Red
            }
        }
    } catch {
        Write-Host "An error occurred while querying applications. Ensure you have sufficient permissions." -ForegroundColor Red
    }
}

Get-AppID
