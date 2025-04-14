Write-Output "Checking GlobalProtect Processes..."

# Function to retrieve running GlobalProtect processes
function Get-GlobalProtectProcesses {
    return Get-Process | Where-Object { $_.ProcessName -like "*PanGPA*" -or $_.ProcessName -like "*PanGPS*" }

        # GlobalProtect Process and Service Management Script
        # This script checks, stops, and restarts GlobalProtect-related processes and services.
        # Author: James ROmeo Gaspar
        # Date: March 28, 2025

}

# Function to retrieve GlobalProtect services
function Get-GlobalProtectServices {
    return Get-Service | Where-Object { $_.DisplayName -like "*GlobalProtect*" -or $_.Name -like "*PanGPS*" }
}

# Function to restart GlobalProtect processes
function Restart-GlobalProtectProcesses {
    try {
        $gpProcesses = Get-GlobalProtectProcesses
        if ($gpProcesses) {
            Write-Output "Stopping GlobalProtect processes..."
            $gpProcesses | ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction Stop }
            Write-Output "GlobalProtect processes have been stopped."
        }

        Write-Output "Starting GlobalProtect processes..."
        Start-Process -FilePath "C:\Program Files\Palo Alto Networks\GlobalProtect\PanGPA.exe" -ErrorAction Stop
        Start-Process -FilePath "C:\Program Files\Palo Alto Networks\GlobalProtect\PanGPS.exe" -ErrorAction Stop
        Write-Output "GlobalProtect processes have been restarted."
    } catch {
        Write-Output "Error restarting GlobalProtect processes: $_"
    }
}

# Function to restart GlobalProtect services
function Restart-GlobalProtectServices {
    try {
        $gpServices = Get-GlobalProtectServices
        if ($gpServices) {
            Write-Output "Restarting GlobalProtect services..."
            $gpServices | ForEach-Object {
                if ($_.Status -eq "Running") {
                    Stop-Service -Name $_.Name -Force -ErrorAction Stop
                }
                Start-Service -Name $_.Name -ErrorAction Stop
            }
            Write-Output "GlobalProtect services have been restarted."
        }
    } catch {
        Write-Output "Error restarting GlobalProtect services: $_"
    }
}

# Function to check and ensure PanGPS service is running
function Check-PanGPSStatus {
    try {
        Write-Output "Verifying if PanGPS service is running..."
        $serviceStatus = Get-Service -Name "PanGPS" -ErrorAction SilentlyContinue
        if ($serviceStatus -and $serviceStatus.Status -ne "Running") {
            Write-Output "PanGPS service is not running. Restarting service..."
            Start-Service -Name "PanGPS" -ErrorAction Stop
            Write-Output "PanGPS service restarted."
        } else {
            Write-Output "PanGPS service is running."
        }
    } catch {
        Write-Output "Error ensuring PanGPS is running: $_"
    }
}

# Execute functions
Restart-GlobalProtectProcesses
Check-PanGPSStatus
Restart-GlobalProtectServices

Write-Output "GlobalProtect Refresh Process Completed."
