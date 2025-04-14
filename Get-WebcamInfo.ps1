function Get-WebcamInfo {
    
    # Script to to retrieve webcam information
    # Author: James Romeo Gaspar
    # Date: 24 January 2025
    # Version 2: Added checks to filter out non-webcam devices and duplicate entries
    # Version 3: 27 January 2025 Modified conditions for Acer devices

    try {
        $webcams = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.Class -eq "ImagingDevice" -or $_.Class -eq "Camera" -and $_.Status -eq "OK" }
    } catch {
        Write-Output "Get-PnpDevice failed. Falling back to Get-WmiObject."
        $webcams = @()
    }

    if (!$webcams -or $webcams.Count -eq 0) {
        $webcams = Get-WmiObject Win32_PnPEntity | Where-Object { $_.Name -match "Camera|Webcam" }
    }

    if ($webcams.Count -eq 0) {
        Write-Output "No webcams detected."
    } else {
        $webcamDetails = @()

        foreach ($webcam in $webcams) {
            if ($webcam.Name -match "Microphone") {
                continue
            }

            $deviceId = $webcam.PNPDeviceID
            $connectionType = if ($deviceId -like "*USB*") {
                if ($webcam.Name -match "Integrated|Built-in|HD User Facing") { 
                    "Built-in"
                } else { 
                    "External" 
                }
            } else {
                "Built-in"
            }
            if ($webcamDetails -notcontains "$($webcam.Name) ($connectionType)") {
                $webcamDetails += "$($webcam.Name) ($connectionType)"
            }
        }
        Write-Output ($webcamDetails -join " | ")
    }
}

Get-WebcamInfo
