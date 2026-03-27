<#
.SYNOPSIS
    Invoke-StandardMsiInstall - The "Golden" MSI Wrapper for Modern UEM Environments.

.DESCRIPTION
    A robust, architected installation wrapper designed for Unified Endpoint Management (UEM) 
    platforms like Workspace ONE, Intune, and SCCM. This script standardizes the deployment 
    lifecycle by handling environmental edge cases that typically cause mid-rollout failures.

.PARAMETER MsiName
    The filename of the MSI to be installed. Must be located in the same directory as the script.

.PARAMETER AppVersion
    The version string used for Registry-based detection logic.

.NOTES
    Non-Negotiables Included:
    1. Multi-fallback pathing (PSScriptRoot / MyInvocation / Get-Location).
    2. Proactive "Mark of the Web" (Zone.Identifier) removal.
    3. Silent execution with suppressed restarts (/qn /norestart).
    4. Verbose MSI logging with auto-cleanup on success.
    5. Custom Registry marker for 100% reliable UEM detection.

    Author: James Romeo Gaspar
    Date:   March 27, 2026
#>

# ==============================================================================
# 1. CONFIGURATION - Change these variables for your specific deployment.
# ==============================================================================
$MsiName    = "YourApplication.msi"
$AppVersion = "1.2.3" 

# ==============================================================================
# 2. PATH DISCOVERY (Triple-Fallback)
# ==============================================================================
$ScriptPath = if ($PSScriptRoot) { 
    $PSScriptRoot 
} elseif ($MyInvocation.MyCommand.Path) { 
    Split-Path $MyInvocation.MyCommand.Path -Parent 
} else { 
    Get-Location 
}

$MsiPath        = Join-Path -Path $ScriptPath -ChildPath $MsiName
$RegistryPath   = "HKLM:\SOFTWARE\CustomDeployments\$($MsiName.Replace('.msi',''))"
$LogDir         = "C:\Temp"
$ScriptLog      = Join-Path -Path $LogDir -ChildPath "Deployment_Audit.log"
$InternalMsiLog = Join-Path -Path $LogDir -ChildPath "$($MsiName)_msi_verbose.log"

# ==============================================================================
# 3. LOGGING & ADMIN GUARDRAILS
# ==============================================================================
function Write-Log {
    param([string]$Message)
    try {
        $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $LogEntry = "[$TimeStamp] $Message"
        if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
        $LogEntry | Out-File -FilePath $ScriptLog -Append -ErrorAction SilentlyContinue
        Write-Host $LogEntry
    } catch {
        Write-Host "LOGGING ERROR: $Message"
    }
}


# ==============================================================================
# 4. THE INSTALLATION PIPELINE
# ==============================================================================
Write-Log "Deployment Started: $MsiName (v$AppVersion)"

try {
    # Verify binary existence
    if (!(Test-Path $MsiPath)) { 
        throw "Binary not found at $MsiPath. Ensure the MSI is in the same folder as the script." 
    }

    # Remove Mark of the Web (Zone.Identifier)
    Write-Log "Unblocking $MsiName (Removing Mark of the Web)..."
    Unblock-File -Path $MsiPath -ErrorAction SilentlyContinue

    # Define silent msiexec arguments
    $Args = "/i `"$MsiPath`" /qn /norestart /L*V `"$InternalMsiLog`""
    
    Write-Log "Executing msiexec.exe with verbose logging..."
    $Process = Start-Process -FilePath "msiexec.exe" -ArgumentList $Args -Wait -PassThru

    # Evaluate Exit Codes (0 = Success, 3010 = Success/Reboot Required)
    if ($Process.ExitCode -eq 0 -or $Process.ExitCode -eq 3010) {
        Write-Log "Success! Exit Code: $($Process.ExitCode)"

        # Set Registry Detection Marker
        Write-Log "Writing Detection Marker to $RegistryPath"
        if (!(Test-Path $RegistryPath)) { New-Item -Path $RegistryPath -Force | Out-Null }
        Set-ItemProperty -Path $RegistryPath -Name "Version" -Value $AppVersion -Force
        Set-ItemProperty -Path $RegistryPath -Name "InstallDate" -Value (Get-Date -Format "yyyyMMdd") -Force

        # Cleanup bulky logs on success
        if (Test-Path $InternalMsiLog) { 
            Write-Log "Cleaning up internal MSI verbose log..."
            Remove-Item -Path $InternalMsiLog -Force 
        }
    } else {
        Write-Log "Install Failed. Exit Code: $($Process.ExitCode). Detailed log preserved at $InternalMsiLog"
        exit $Process.ExitCode
    }

} catch {
    Write-Log "FATAL ERROR: $($_.Exception.Message)"
    exit 1
}

Write-Log "Deployment Finished."
