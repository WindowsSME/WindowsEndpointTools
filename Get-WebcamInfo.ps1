<#
.SYNOPSIS
    Retrieves information about connected webcam devices on the system.

.DESCRIPTION
    This function checks for all imaging or camera devices using `Get-PnpDevice`. 
    If that fails or returns no results, it falls back to using `Get-WmiObject`.
    It gathers details such as whether the device is internal or external and its status (enabled/disabled).
    The function filters out microphones and avoids duplicate entries.

.NOTES
    Author: James Romeo Gaspar
    Creation Date: 24 January 2025

.CHANGELOG
    # Version 2: Added checks to filter out non-webcam devices and duplicate entries
    # Version 3: Modified conditions for Acer devices
    # Version 4: Added capability to check if webcam device is disabled / enabled
#>

function Get-WebcamInfo {
    try {
        # Attempt to retrieve all imaging and camera devices regardless of status
        $webcams = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { 
            $_.Class -in @("ImagingDevice", "Camera")
        }
    } catch {
        # If Get-PnpDevice fails, fallback to WMI-based approach
        Write-Output "Get-PnpDevice failed. Falling back to Get-WmiObject."
        $webcams = @()
    }

    # Use fallback if no webcams were found
    if (!$webcams -or $webcams.Count -eq 0) {
        $webcams = Get-WmiObject Win32_PnPEntity | Where-Object { 
            $_.Name -match "Camera|Webcam"
        }
    }

    # If no webcams are detected, inform the user
    if ($webcams.Count -eq 0) {
        Write-Output "No webcams detected."
    } else {
        $webcamDetails = @()

        foreach ($webcam in $webcams) {
            # Skip entries that appear to be microphones
            if ($webcam.Name -match "Microphone") {
                continue
            }

            # Determine connection type based on device ID and name
            $deviceId = $webcam.PNPDeviceID
            $connectionType = if ($deviceId -like "*USB*") {
                if ($webcam.Name -match "Integrated|Internal|HD User Facing") { 
                    "Internal"
                } else { 
                    "External" 
                }
            } else {
                "Internal"
            }

            # Determine device status (enabled/disabled/unknown)
            $enabled = "Unknown"
            if ($webcam.Status -eq "OK") {
                $enabled = "Enabled"
            } elseif ($webcam.Status -eq "Error" -or $webcam.Status -eq "Unknown") {
                $enabled = "Disabled"
            } elseif ($null -ne $webcam.ConfigManagerErrorCode) {
                $enabled = if ($webcam.ConfigManagerErrorCode -eq 0) { "Enabled" } else { "Disabled" }
            }

            # Format status string for output
            $status = "$($webcam.Name) ($connectionType) - $enabled"

            # Avoid duplicate entries in output
            if ($webcamDetails -notcontains $status) {
                $webcamDetails += $status
            }
        }

        # Output all collected webcam details
        Write-Output ($webcamDetails -join " | ")
    }
}

# Run the function
Get-WebcamInfo
