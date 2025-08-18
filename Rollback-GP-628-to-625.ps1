<#
.SYNOPSIS
    Roll back Palo Alto GlobalProtect from 6.2.8 to 6.2.5 with portal settings preserved.

.DESCRIPTION
    This script:
      1) Detects installed GlobalProtect via MSI uninstall registry keys.
      2) Captures existing portal URLs and "last used" portal, filtered to those containing 'jaroga'.
      3) Stops GlobalProtect services/processes cleanly.
      4) Uninstalls GlobalProtect 6.2.8 by ProductCode (msiexec /x).
      5) Installs GlobalProtect 6.2.5 from an MSI located in the script folder (first match: GlobalProtect64-6.2.5*.msi).
      6) Restores portal configuration to HKLM/HKCU (Portal, LastUrl, per-portal subkeys) and clears legacy PortalList values.
      7) Re-enables and starts services; launches PanGPA UI if needed.
      8) Verifies final version and returns an appropriate exit code.

.PARAMETER (none)
    Versions and paths are defined in-script:
      $FromVer = '6.2.8'
      $ToVer   = '6.2.5'
      $LogFile = 'C:\Temp\Restore-625.txt'
      Portal filter: IncludeWord = 'jaroga'

.REQUIREMENTS
    - Run as Administrator (elevated PowerShell).
    - Windows with MSIEXEC available.
    - 64-bit GlobalProtect MSI file named like: GlobalProtect64-6.2.5*.msi
      placed in the same directory as this script.
    - Writes logs to C:\Temp\Restore-625.txt (folder auto-created).

.LOGGING
    Appends timestamped entries to: C:\Temp\Restore-625.txt
    Also writes concise status messages to standard output.

.EXIT CODES
      0  Success (already on target or rollback completed).
      1  Failure (missing MSI, uninstall/install error, missing ProductCode, or unexpected final version).

.SAFETY & BEHAVIOR
    - $ErrorActionPreference = 'Stop' ensures early failure on errors.
    - Services PanGPS/PanGPA are disabled/stopped during rollback, then set back to Automatic.
    - Processes PanGPS/PanGPA/GlobalProtect are force-terminated if still running.
    - Registry touched:
        HKLM:\SOFTWARE\Palo Alto Networks\GlobalProtect\{Settings,PanSetup}
        HKCU:\Software\Palo Alto Networks\GlobalProtect\Settings
      Keys 'Portal' and 'LastUrl' are set to the filtered last-used portal (or first match).
      Per-portal subkeys are recreated; legacy 'PortalList' values are removed.

.IDEMPOTENCE
    - If already on 6.2.5, exits with 0 and logs "No action".
    - If 6.2.8 is not detected, exits with 0 and logs "No action".

.EXAMPLE
    PS> .\Rollback-GP-628-to-625.ps1
    Rolls back GlobalProtect 6.2.8 to 6.2.5 silently, restores jaroga portals, and writes a log to C:\Temp\Restore-625.txt.

.NOTES
    Author: James Romeo Gaspar
    Last Updated: August 18, 2025
    Tested on: Windows 10/11 x64
#>


$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'

# Log file
$LogFile = "C:\Temp\Restore-625.txt"
if (-not (Test-Path "C:\Temp")) { New-Item -Path "C:\Temp" -ItemType Directory -Force | Out-Null }

function Write-Log {
    param([string]$msg)
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Add-Content -Path $LogFile -Value "$timestamp : $msg"
}

Write-Log "=== Rollback started ==="
Write-Log "Portal filter hardcoded: IncludeWord='jaroga'"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$GP625Msi = Get-ChildItem -Path $ScriptDir -Filter 'GlobalProtect64-6.2.5*.msi' -ErrorAction SilentlyContinue |
            Select-Object -First 1

$FromVer = '6.2.8'
$ToVer   = '6.2.5'
$UninstallRoots = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)

function Get-GPEntries {
    foreach ($root in $UninstallRoots) {
        foreach ($key in (Get-ChildItem $root -ErrorAction SilentlyContinue)) {
            try {
                $p = Get-ItemProperty -Path $key.PSPath -ErrorAction Stop
                if ($p.DisplayName -match '^GlobalProtect' -and $p.DisplayVersion) {
                    $guid = $null
                    if ($p.UninstallString -match '\{[0-9A-Fa-f-]+\}') { $guid = $Matches[0] }
                    [pscustomobject]@{
                        DisplayName     = $p.DisplayName
                        DisplayVersion  = $p.DisplayVersion
                        UninstallString = $p.UninstallString
                        ProductCode     = $guid
                    }
                }
            } catch {}
        }
    }
}

function Get-GPVersion {
    $ver = $null
    foreach ($e in Get-GPEntries) { if ($e.DisplayVersion) { $ver = $e.DisplayVersion } }
    return $ver
}


function Get-GPPortalsAndLastUsed {
    param([string]$IncludeWord)

    $all = New-Object System.Collections.Generic.List[string]
    $lastUsed = $null

    $hkmlPanSetup   = 'HKLM:\SOFTWARE\Palo Alto Networks\GlobalProtect\PanSetup'
    $hkmlSettings   = 'HKLM:\SOFTWARE\Palo Alto Networks\GlobalProtect\Settings'

    foreach ($path in @($hkmlPanSetup,$hkmlSettings)) {
        if (Test-Path $path) {
            try {
                $props = Get-ItemProperty -Path $path -ErrorAction Stop
                foreach ($name in @('Portal')) {
                    if ($props.PSObject.Properties.Name -contains $name -and $props.$name) {
                        $v = $props.$name.ToString().Trim()
                        if ($v -and -not $all.Contains($v)) { [void]$all.Add($v) }
                    }
                }
                if ($path -eq $hkmlSettings) {
                    foreach ($name in @('LastUrl')) {
                        if ($props.PSObject.Properties.Name -contains $name -and $props.$name) {
                            $lu = $props.$name.ToString().Trim()
                            if (-not $lastUsed -and $lu) { $lastUsed = $lu }
                            if ($lu -and -not $all.Contains($lu)) { [void]$all.Add($lu) }
                        }
                    }
                }
            } catch {}

            if ($path -eq $hkmlSettings) {
                Get-ChildItem $path -ErrorAction SilentlyContinue | Where-Object PSIsContainer | ForEach-Object {
                    $n = $_.PSChildName.Trim()
                    if ($n -and -not $all.Contains($n)) { [void]$all.Add($n) }
                }
            }
        }
    }

    $hkcuSettings = 'HKCU:\Software\Palo Alto Networks\GlobalProtect\Settings'
    if (Test-Path $hkcuSettings) {
        try {
            $props = Get-ItemProperty -Path $hkcuSettings -ErrorAction Stop
            foreach ($name in @('Portal','LastUrl')) {
                if ($props.PSObject.Properties.Name -contains $name -and $props.$name) {
                    $v = $props.$name.ToString().Trim()
                    if ($name -eq 'LastUrl' -and -not $lastUsed -and $v) { $lastUsed = $v }
                    if ($v -and -not $all.Contains($v)) { [void]$all.Add($v) }
                }
            }
        } catch {}
        Get-ChildItem $hkcuSettings -ErrorAction SilentlyContinue | Where-Object PSIsContainer | ForEach-Object {
            $n = $_.PSChildName.Trim()
            if ($n -and -not $all.Contains($n)) { [void]$all.Add($n) }
        }
    }

    $merged = $all | Select-Object -Unique
    if ($IncludeWord) { $merged = $merged | Where-Object { $_ -like "*$IncludeWord*" } }

    $effectiveLast = $lastUsed
    if ($IncludeWord -and $effectiveLast -and ($effectiveLast -notlike "*$IncludeWord*")) { $effectiveLast = $null }
    if (-not $effectiveLast -and $merged.Count -gt 0) { $effectiveLast = $merged[0] }

    [pscustomobject]@{
        Portals  = $merged
        LastUsed = $effectiveLast
    }
}

function Set-GPPortalsAccurate {
    param(
        [string]  $Primary,
        [string[]]$AllPortals
    )

    $clean = $AllPortals | Where-Object { $_ -and $_.Trim() } | ForEach-Object { $_.Trim() } | Select-Object -Unique
    $primary = if ($Primary -and $Primary.Trim()) { $Primary.Trim() } elseif ($clean.Count -gt 0) { $clean[0] } else { $null }

    $hkmlSettings = 'HKLM:\SOFTWARE\Palo Alto Networks\GlobalProtect\Settings'
    $hkmlPanSetup = 'HKLM:\SOFTWARE\Palo Alto Networks\GlobalProtect\PanSetup'
    $hkcuSettings = 'HKCU:\Software\Palo Alto Networks\GlobalProtect\Settings'

    foreach ($path in @($hkmlPanSetup,$hkmlSettings,$hkcuSettings)) {
        try {
            if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        } catch {}
    }

    if ($primary) {
        try { New-ItemProperty -Path $hkmlSettings -Name 'Portal'  -Value $primary -PropertyType String -Force | Out-Null } catch {}
        try { New-ItemProperty -Path $hkmlSettings -Name 'LastUrl' -Value $primary -PropertyType String -Force | Out-Null } catch {}
        try { New-ItemProperty -Path $hkcuSettings -Name 'Portal'  -Value $primary -PropertyType String -Force | Out-Null } catch {}
        try { New-ItemProperty -Path $hkcuSettings -Name 'LastUrl' -Value $primary -PropertyType String -Force | Out-Null } catch {}
        try { New-ItemProperty -Path $hkmlPanSetup -Name 'Portal'  -Value $primary -PropertyType String -Force | Out-Null } catch {}
    }

    foreach ($p in $clean) {
        try { New-Item -Path (Join-Path $hkmlSettings $p) -Force | Out-Null } catch {}
        try { New-Item -Path (Join-Path $hkcuSettings $p) -Force | Out-Null } catch {}
    }

    foreach ($path in @($hkmlSettings,$hkcuSettings,$hkmlPanSetup)) {
        foreach ($name in @('PortalList')) {
            try { Remove-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue } catch {}
        }
    }
}


function Stop-GP {
    $services = @('PanGPS','PanGPA')

    foreach ($svc in $services) {
        try { Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue } catch {}
        try { & sc.exe stop $svc | Out-Null } catch {}
    }

    $deadline = (Get-Date).AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 500
        $stillRunning = $false
        foreach ($svc in $services) {
            try {
                $status = (Get-Service -Name $svc -ErrorAction SilentlyContinue).Status
                if ($status -and $status -ne 'Stopped') { $stillRunning = $true }
            } catch {}
        }
    } while ($stillRunning -and (Get-Date) -lt $deadline)

    $procs = @('PanGPS','PanGPA','GlobalProtect')
    foreach ($pr in $procs) {
        try { Get-Process -Name $pr -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue } catch {}
    }
    Start-Sleep -Seconds 2
}

function Start-GP {
    $services = @('PanGPS','PanGPA')

    foreach ($svc in $services) {
        try {
            sc.exe config $svc start= auto | Out-Null
            Set-Service -Name $svc -StartupType Automatic -ErrorAction SilentlyContinue
        } catch {}

        $ok = $false
        for ($i=0; $i -lt 5 -and -not $ok; $i++) {
            try {
                Start-Service -Name $svc -ErrorAction Stop
                Start-Sleep -Seconds 2
                $status = (Get-Service -Name $svc -ErrorAction SilentlyContinue).Status
                if ($status -eq 'Running') { $ok = $true }
            } catch {
                Start-Sleep -Seconds 2
            }
        }
        if (-not $ok) { Write-Log "ERROR: Failed to start service $svc" } else { Write-Log "Started service $svc" }
    }

    Start-Sleep -Seconds 2
    if (-not (Get-Process -Name "PanGPA" -ErrorAction SilentlyContinue)) {
        $uiPath = Join-Path $env:ProgramFiles 'Palo Alto Networks\GlobalProtect\PanGPA.exe'
        if (Test-Path $uiPath) {
            try { Start-Process -FilePath $uiPath -ErrorAction SilentlyContinue ; Write-Log "Launched PanGPA.exe" } catch { Write-Log "WARN: Could not launch PanGPA.exe" }
        }
    }
}


try {
    if (-not $GP625Msi) {
        Write-Log "ERROR: 6.2.5 MSI not found in package folder."
        Write-Output "Rollback failed: 6.2.5 MSI not found."
        exit 1
    }

    $cap = Get-GPPortalsAndLastUsed -IncludeWord "jaroga"
    $SavedPortals    = $cap.Portals
    $LastUsedPortal  = $cap.LastUsed
    Write-Log ("Captured portals (filtered): " + ($(if ($SavedPortals) { $SavedPortals -join ';' } else { '<none>' })))
    Write-Log ("Captured last-used portal (filtered): " + ($(if ($LastUsedPortal) { $LastUsedPortal } else { '<none>' })))

    $current = Get-GPVersion
    Write-Log "Current GlobalProtect version: ${current:-'none'}"

    if ($current -like "$ToVer*") {
        Write-Log "Already at $ToVer. No action."
        Write-Output "Already at GlobalProtect $ToVer. No action."
        exit 0
    }

    if ($current -notlike "$FromVer*") {
        Write-Log "Target version $FromVer not found. No action."
        Write-Output "GlobalProtect $FromVer not detected. No action."
        exit 0
    }

    $entry = Get-GPEntries | Where-Object { $_.DisplayVersion -like "$FromVer*" } | Select-Object -First 1
    if (-not $entry) {
        Write-Log "ERROR: Uninstall entry for $FromVer not found."
        Write-Output "Rollback failed: uninstall entry not found."
        exit 1
    }

    $guid = $entry.ProductCode
    if (-not $guid -and $entry.UninstallString -match '\{[0-9A-Fa-f-]+\}') { $guid = $Matches[0] }
    if (-not $guid) {
        Write-Log "ERROR: ProductCode missing for $FromVer."
        Write-Output "Rollback failed: ProductCode missing."
        exit 1
    }

    Stop-GP

    Write-Log "Uninstalling $FromVer ..."
    $unArgs = "/x $guid /qn /norestart REBOOT=ReallySuppress"
    $un = Start-Process -FilePath "msiexec.exe" -ArgumentList $unArgs -Wait -PassThru -WindowStyle Hidden
    Write-Log "Uninstall exit code: $($un.ExitCode)"
    if ($un.ExitCode -ne 0) {
        Write-Output "Rollback failed: uninstall $FromVer exit code $($un.ExitCode)."
        exit 1
    }

    Write-Log "Installing $ToVer ..."
    $inArgs = "/i `"$($GP625Msi.FullName)`" /qn /norestart REBOOT=ReallySuppress"
    $in = Start-Process -FilePath "msiexec.exe" -ArgumentList $inArgs -Wait -PassThru -WindowStyle Hidden
    Write-Log "Install exit code: $($in.ExitCode)"
    if ($in.ExitCode -ne 0) {
        Write-Output "Rollback failed: install $ToVer exit code $($in.ExitCode)."
        exit 1
    }

    if ($SavedPortals -and $SavedPortals.Count -gt 0) {
        Set-GPPortalsAccurate -Primary $LastUsedPortal -AllPortals $SavedPortals
        Write-Log ("Restored portals (subkeys): " + ($SavedPortals -join ';'))
        Write-Log ("Restored active portal: " + ($(if ($LastUsedPortal) { $LastUsedPortal } else { $SavedPortals[0] })))
    } else {
        Write-Log "No portals to restore (after filter)."
    }

    Start-GP

    $final = Get-GPVersion
    Write-Log "Final version after rollback: $final"

    if ($final -like "$ToVer*") {
        Write-Log "SUCCESS: Rollback $FromVer > $ToVer completed."
        Write-Output "Rollback completed successfully: GlobalProtect $FromVer > $ToVer."
        exit 0
    } else {
        Write-Log "ERROR: Rollback failed, expected $ToVer but found $final."
        Write-Output "Rollback failed: expected $ToVer, found '$final'."
        exit 1
    }
}
catch {
    $err = ($_ | Out-String).Trim()
    Write-Log "EXCEPTION: $err"
    Write-Output "Rollback failed: $err"
    exit 1
}
