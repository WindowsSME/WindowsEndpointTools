<#
.SYNOPSIS
Reinstall Workspace ONE Intelligent Hub/Agent safely: backup keys, uninstall all WS1 components, download latest MSI, reinstall via Windows Installer COM, and relaunch Hub.

.DESCRIPTION
This script performs a full Workspace ONE Intelligent Hub/Agent refit on Windows:
- Backs up and blanks WS1 deployment manifest values to prevent stale deployments.
- Uninstalls WS1 MSI/EXE entries and removes the WS1 APPX for all users.
- Waits for MSI to become idle (with live elapsed-time logging).
- Optionally downloads the MSI (reusing a recent, checksum-verified copy if present).
- Installs the MSI securely via the Windows Installer COM API (STA) with retries for 1618.
- Optionally passes enrollment properties (SERVER/LGName/USERNAME/PASSWORD).
- Launches Hub non-elevated when possible.
- All actions are logged to a timestamped log file; transcripts are optional via -EnableTranscript.

.PARAMETER DownloadUrl
Direct URL to the WS1/Airwatch Agent MSI to download. Defaults to the current public Omnissa package URL.

.PARAMETER OutFile
Local path to save the MSI (and reuse if fresh/valid). Default: C:\Temp\AirwatchAgent.msi

.PARAMETER Sha256
Optional expected SHA-256 checksum of the MSI. If provided, the file is verified (both reused and downloaded cases).

.PARAMETER Enroll
Whether to set ENROLL=Y/N MSI property. Default: N

.PARAMETER AssignToLoggedInUser
Sets ASSIGNTOLOGGEDINUSER=Y/N during install. Default: N

.PARAMETER EnableMsiLogging
Enables MSI native logging during install (to %TEMP%\AirwatchAgent_install_*.log).

.PARAMETER MsiLogLevel
MSI log verbosity (Minimal|Verbose). Default: Verbose

.PARAMETER MaxAgeDays
If an existing MSI at -OutFile is newer than this many days and large enough (>=100 KB), it may be reused. Default: 7

.PARAMETER Server
Optional Workspace ONE UEM server URL passed to MSI as SERVER=...

.PARAMETER GroupID
Optional Organization Group identifier passed as LGName=...

.PARAMETER Username
Optional staging USERNAME for enrollment. If set, you can also pass -Password.

.PARAMETER Password
Optional staging PASSWORD (SecureString). Only used when -Username is supplied.

.PARAMETER NonInteractive
Skips interactive prompts.

.PARAMETER EnableTranscript
If supplied, starts a PowerShell transcript in %ProgramData% with a timestamped filename.

.EXAMPLE
# Default, interactive using the built-in download URL and reuse window
.\Reinstall-WS1Hub.ps1

.EXAMPLE
# Non-interactive, with explicit enrollment and MSI logging
.\Reinstall-WS1Hub.ps1 -NonInteractive -Enroll Y -AssignToLoggedInUser N `
  -Server "https://uem.contoso.com" -GroupID "ACME" -Username "staging@contoso.com" `
  -Password (Read-Host "Pwd" -AsSecureString) -EnableMsiLogging -MsiLogLevel Verbose

.EXAMPLE
# Reuse MSI if fresh, otherwise download; verify checksum; show transcript
.\Reinstall-WS1Hub.ps1 -OutFile C:\Temp\Hub.msi -Sha256 "abcd1234..." -EnableTranscript

.REQUIREMENTS
- Run as Administrator.
- Windows with Windows Installer service available.
- PowerShell 5.1+ (or PowerShell 7+ with Windows compatibility for COM).

.LOGGING
- Script log: C:\Temp\ws1_backup_uninstall_<yyyyMMdd_HHmmss>.log
- Optional transcript (if -EnableTranscript): %ProgramData%\ws1_backup_uninstall_<timestamp>.trn
- Optional MSI log (if -EnableMsiLogging): %TEMP%\AirwatchAgent_install_<timestamp>.log

.NOTES
- Uses SupportsShouldProcess; you can test with -WhatIf.
- Handles MSI busy/1618 with retries and clear elapsed-time messages.
- Cleans residual registry keys and AirWatch-issued device certs (scoped patterns).

.AUTHOR
James Romeo Gaspar
August 29, 2025

#>


[CmdletBinding(SupportsShouldProcess)]
param(
  [string]$DownloadUrl = "https://packages.omnissa.com/wsone/AirwatchAgent.msi",
  [string]$OutFile     = "C:\Temp\AirwatchAgent.msi",
  [string]$Sha256,
  [ValidateSet('Y','N')][string]$Enroll = 'N',
  [ValidateSet('Y','N')][string]$AssignToLoggedInUser = 'N',
  [switch]$EnableMsiLogging,
  [ValidateSet('Minimal','Verbose')][string]$MsiLogLevel = 'Verbose',
  [int]$MaxAgeDays = 7,

  [string]$Server,
  [string]$GroupID,
  [string]$Username,
  [securestring]$Password,
  [switch]$NonInteractive,

  [switch]$EnableTranscript
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------- Logging ----------
$DateNow = Get-Date -Format 'yyyyMMdd_HHmmss'
$LogFile = "C:\Temp\ws1_backup_uninstall_$DateNow.log"
function Log { param([string]$m,[string]$lvl='INFO')
  $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  "$ts`t($lvl)`t$m" | Tee-Object -FilePath $LogFile -Append
}

# Optional transcript
if ($EnableTranscript) {
  try {
    $trnPath = Join-Path $env:ProgramData ("ws1_backup_uninstall_{0}.trn" -f $DateNow)
    Start-Transcript -Path $trnPath -ErrorAction SilentlyContinue
    Log ("Transcript enabled at {0}" -f $trnPath)
  } catch {
    Log ("Transcript start failed: {0}" -f $_.Exception.Message) 'WARNING'
  }
}

# ---------- Helpers ----------
function Test-Admin {
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).
             IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
  if (-not $isAdmin) {
    Write-Host "This script must be run as Administrator." -ForegroundColor Red
    exit 1
  }
}

function ConvertFrom-CmdLine([string]$s) {
  if ($s -match '^\s*"([^"]+)"\s*(.*)$') { return ,$Matches[1],$Matches[2] }
  elseif ($s -match '^\s*(\S+)\s*(.*)$') { return ,$Matches[1],$Matches[2] }
  else { return ,$s,'' }
}

# --- WS1 uninstall detection ---
function Get-Ws1UninstallEntries {
  $paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
  )
  $patterns = '(?i)^(VMware(?! Tools)|.*Workspace ONE)'

  @(
    foreach ($root in $paths) {
      Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
        try {
          $ip = Get-ItemProperty $_.PsPath -ErrorAction Stop
          $dn = if ($ip.PSObject.Properties['DisplayName']) { $ip.PSObject.Properties['DisplayName'].Value } else { $null }
          if ($dn -and $dn -match $patterns) { $dn }
        } catch { }
      }
    }
  ) | Sort-Object -Unique
}

# --- Wait: Windows Installer idle ---
function Wait-ForInstallerIdle {
  [CmdletBinding()]
  param(
    [int]$TimeoutSec = 480,
    [int]$PollMs = 2000
  )

  $sw = [Diagnostics.Stopwatch]::StartNew()
  $timeoutMin = [math]::Round($TimeoutSec / 60.0, 1)

  # initial banner
  Log ("Waiting for Windows Installer to be idle... (elapsed: {0}, timeout: {1}s ≈ {2} min)" -f "0s", $TimeoutSec, $timeoutMin)

  do {
    $msiBusy    = Get-Process msiexec -ErrorAction SilentlyContinue
    $inProgress = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\InProgress'

    if (-not $msiBusy -and -not $inProgress) {
      Log ("Windows Installer is idle. (elapsed: {0:N0}s)" -f $sw.Elapsed.TotalSeconds) 'SUCCESS'
      return $true
    }

    Log ("Windows Installer busy... still waiting (elapsed: {0:N0}s)" -f $sw.Elapsed.TotalSeconds)
    Start-Sleep -Milliseconds $PollMs
  } while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec)

  Log ("Windows Installer still busy after {0}s (≈ {1} min)." -f $TimeoutSec, $timeoutMin) 'WARNING'
  return $false
}

# --- Wait: WS1 uninstall done ---
function Wait-ForUninstallIdle {
  [CmdletBinding()]
  param(
    [int]$TimeoutSec = 900,
    [int]$PollMs = 1000
  )

  $sw = [Diagnostics.Stopwatch]::StartNew()
  $timeoutMin = [math]::Round($TimeoutSec / 60.0, 1)

  # initial banner
  Log ("Waiting for Workspace ONE components to uninstall... (elapsed: {0}, timeout: {1}s ≈ {2} min)" -f "0s", $TimeoutSec, $timeoutMin)

  do {
    $remaining = Get-Ws1UninstallEntries
    if (-not $remaining -or $remaining.Count -eq 0) {
      Log ("Uninstall verification passed; no matching products remain. (elapsed: {0:N0}s)" -f $sw.Elapsed.TotalSeconds) 'SUCCESS'
      return $true
    }

    Log ("Uninstall still in progress... remaining: {0} (elapsed: {1:N0}s / {2}s)" -f `
         ($remaining -join ', '), $sw.Elapsed.TotalSeconds, $TimeoutSec)

    Start-Sleep -Milliseconds $PollMs
  } while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec)

  Log ("Timeout waiting for uninstall. Still present: {0}" -f ($remaining -join ', ')) 'WARNING'
  return $false
}

# ---------- Stage 1: Backup + Uninstall ----------
function Invoke-BackupAndUninstall {
  [CmdletBinding(SupportsShouldProcess)]
  param()

  try {
    Log "Starting backup + uninstall stage"

    foreach ($svcName in 'VMware AirWatch Agent Service','AirWatchMDM','AW.AgentSvc') {
      try {
        $svc = Get-Service $svcName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
          if ($PSCmdlet.ShouldProcess($svcName,"Stop-Service -Force")) {
            Stop-Service $svcName -Force -ErrorAction SilentlyContinue
            Log "Stopped service: $svcName"
          }
        }
      } catch { Log ("Service stop warn ({0}): {1}" -f $svcName, $_.Exception.Message) 'WARNING' }
    }

    $base   = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\AirWatchMDM\AppDeploymentAgent\AppManifests'
    try {
      $apps = (Get-ItemProperty -Path "$base\*" -ErrorAction SilentlyContinue).PSChildname
      foreach ($app in $apps) {
        try {
          $path = "$base\$app"
          $val = (Get-ItemProperty -Path $path -Name 'DeploymentManifestXML' -ErrorAction SilentlyContinue).'DeploymentManifestXML'
          if ($null -ne $val) {
            if ($PSCmdlet.ShouldProcess("$path\DeploymentManifestXML", "Backup+Blank")) {
              Rename-ItemProperty -Path $path -Name 'DeploymentManifestXML' -NewName 'DeploymentManifestXML_BAK' -ErrorAction SilentlyContinue
              New-ItemProperty -Path $path -Name 'DeploymentManifestXML' -Value '' -PropertyType String -Force | Out-Null
              Log ("Backed up DeploymentManifestXML for {0}" -f $app)
            }
          }
        } catch { Log ("Manifest backup warn for {0}: {1}" -f $app, $_.Exception.Message) 'WARNING' }
      }
    } catch { Log ("Manifest enumeration warn: {0}" -f $_.Exception.Message) 'WARNING' }

    Log "Uninstalling Workspace ONE Hub/Agent (MSI/EXE)"
    $paths = @(
      'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
      'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $patterns = '(?i)^(VMware(?! Tools)|.*Workspace ONE)'

    $products = foreach ($root in $paths) {
      Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
        try {
          $ip = Get-ItemProperty $_.PsPath -ErrorAction Stop
          $dn = if ($ip.PSObject.Properties['DisplayName']) { $ip.PSObject.Properties['DisplayName'].Value } else { $null }
          $un = if ($ip.PSObject.Properties['UninstallString']) { $ip.PSObject.Properties['UninstallString'].Value } else { $null }
          $qu = if ($ip.PSObject.Properties['QuietUninstallString']) { $ip.PSObject.Properties['QuietUninstallString'].Value } else { $null }

          if ($dn -and ($un -or $qu) -and $dn -match $patterns) {
            [pscustomobject]@{ DisplayName=$dn; UninstallString=$un; QuietUninstallString=$qu }
          }
        } catch {
          Log ("Uninstall key read warn {0}: {1}" -f $_.PsPath, $_.Exception.Message) 'WARNING'
        }
      }
    }

    function Invoke-Uninstall {
      param(
        [string]$DisplayName,
        [string]$UninstallString,
        [string]$QuietUninstallString
      )
      try {
        if (-not ($UninstallString -or $QuietUninstallString)) {
          Log ("Skip {0}: no uninstall strings" -f $DisplayName) 'WARNING'
          return
        }
        $cmd,$args = if ($QuietUninstallString) { ConvertFrom-CmdLine $QuietUninstallString } else { ConvertFrom-CmdLine $UninstallString }
        if (-not $cmd) { Log ("Skip {0}: parsed empty command" -f $DisplayName) 'WARNING'; return }

        if ($cmd -match '(?i)msiexec(\.exe)?$' -and $args -match '/X\s*({[^}]+})') {
          $alist = @('/X', $Matches[1], '/qn', 'REBOOT=ReallySuppress')
          Log ("Running msiexec {0} for {1}" -f ($alist -join ' '), $DisplayName)
          if ($PSCmdlet.ShouldProcess($DisplayName,"msiexec /X")) {
            $code = (Start-Process msiexec.exe -ArgumentList $alist -PassThru -Wait).ExitCode
            Log ("Uninstall of {0} exit code: {1}" -f $DisplayName, $code)
          }
        } elseif ($cmd -match '(?i)\.(exe|cmd|bat)$') {
          if ($PSCmdlet.ShouldProcess($DisplayName,"$cmd $args")) {
            Log ("Running quiet uninstall: {0} {1} for {2}" -f $cmd, $args, $DisplayName)
            $code = (Start-Process $cmd -ArgumentList $args -PassThru -Wait).ExitCode
            Log ("Uninstall of {0} exit code: {1}" -f $DisplayName, $code)
          }
        } else {
          if ($args -match '({[^}]+})') {
            if ($PSCmdlet.ShouldProcess($DisplayName,"msiexec /X {GUID}")) {
              $code = (Start-Process msiexec.exe -ArgumentList '/X',$Matches[1],'/qn','REBOOT=ReallySuppress' -PassThru -Wait).ExitCode
              Log ("Uninstall of {0} exit code: {1}" -f $DisplayName, $code)
            }
          } else {
            Log ("Unknown uninstall format for {0}: {1} {2}" -f $DisplayName, $cmd, $args) 'WARNING'
          }
        }
      } catch {
        Log ("Uninstall error for {0}: {1}" -f $DisplayName, $_.Exception.Message) 'WARNING'
      }
    }

    foreach ($p in $products) {
      try { Invoke-Uninstall -DisplayName $p.DisplayName -UninstallString $p.UninstallString -QuietUninstallString $p.QuietUninstallString }
      catch { Log ("Uninstall dispatch warn for {0}: {1}" -f ($p.DisplayName -as [string]), $_.Exception.Message) 'WARNING' }
    }

    Log "Verifying products are removed..."
    [void](Wait-ForUninstallIdle -TimeoutSec 900)

    Log ("Waiting for Windows Installer to be idle... (timeout: {0}s ≈ {1} min)" -f 900, [math]::Round(900/60.0,1))
    [void](Wait-ForInstallerIdle -TimeoutSec 900 -PollMs 1000)

    Log "Removing Workspace ONE Hub APPX for all users"
    try {
      Get-AppxPackage -AllUsers -Name '*AirwatchLLC*' -ErrorAction SilentlyContinue | ForEach-Object {
        try {
          if ($PSCmdlet.ShouldProcess($_.PackageFullName,"Remove-AppxPackage -AllUsers")) {
            Log ("Remove-AppxPackage -AllUsers {0}" -f $_.PackageFullName)
            Remove-AppxPackage -AllUsers -Package $_.PackageFullName -Confirm:$false -ErrorAction Stop
          }
        } catch { Log ("APPX removal warn ({0}): {1}" -f $_.PackageFullName, $_.Exception.Message) 'WARNING' }
      }
    } catch { Log ("APPX enumeration warn: {0}" -f $_.Exception.Message) 'WARNING' }

    Log "Cleaning residual registry keys"
    foreach ($rk in @(
      'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\AirWatch',
      'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\AirWatchMDM'
    )) {
      try {
        if ($PSCmdlet.ShouldProcess($rk, "Remove-Item -Recurse -Force")) {
          Remove-Item -Path $rk -Recurse -Force -ErrorAction Stop
          Log ("Removed {0}" -f $rk)
        }
      } catch { Log ("Registry cleanup warn ({0}): {1}" -f $rk, $_.Exception.Message) 'WARNING' }
    }

    Log "Deleting device certs issued by AirWatch (scoped match)"
    $scopes = @('LocalMachine','CurrentUser')
    $stores = @('My','CA','Root','TrustedPeople','TrustedPublisher')
    foreach ($scope in $scopes) {
      foreach ($store in $stores) {
        $storePath = "cert:$scope\$store"
        try {
          Get-ChildItem -Path $storePath -ErrorAction Stop |
            Where-Object { $_.Issuer -like '*AirWatch*' -or $_.Issuer -like '*VMware Issuing*' -or $_.Subject -like '*AwDeviceRoot*' } |
            ForEach-Object {
              try {
                if ($PSCmdlet.ShouldProcess("$storePath -> $($_.Subject)", "Remove certificate")) {
                  Log ("Removing cert from {0}: {1}" -f $storePath, $_.Subject)
                  Remove-Item -Path $_.PSPath -Force -ErrorAction Stop
                }
              } catch {
                Log ("Cert removal warn ({0} in {1}): {2}" -f $_.Subject, $storePath, $_.Exception.Message) 'WARNING'
              }
            }
        } catch {
          Log ("Cert store access warn ({0}): {1}" -f $storePath, $_.Exception.Message) 'WARNING'
        }
      }
    }

    Log "Backup + uninstall stage complete" 'SUCCESS'
    Log ("Log file: {0}" -f $LogFile)
  }
  catch {
    Log ("ERROR: {0}" -f $_.Exception.Message) 'ERROR'
    throw
  }
}

# ---------- Stage 2: Download ----------
function Save-WS1AgentInstaller {
  [CmdletBinding()]
  param([int]$MaxAgeDays = 7)

  $dir = Split-Path -Parent $OutFile
  if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

  $reuse = $false
  if (Test-Path $OutFile) {
    $fi  = Get-Item $OutFile
    $age = (Get-Date) - $fi.LastWriteTime
    if ($age.TotalDays -le $MaxAgeDays -and $fi.Length -ge 100000) {
      if ($Sha256) {
        try {
          $actual = (Get-FileHash -Algorithm SHA256 -Path $OutFile).Hash.ToLowerInvariant()
          if ($actual -eq $Sha256.ToLowerInvariant()) {
            Log ("Using existing MSI (age: {0:N1} days, size: {1} bytes, hash OK). Skipping download." -f $age.TotalDays, $fi.Length)
            $reuse = $true
          } else {
            Log ("Existing MSI hash mismatch (expected {0}, got {1}). Re-downloading." -f $Sha256, $actual) 'WARNING'
          }
        } catch {
          Log ("Failed to hash existing MSI. Re-downloading. Error: {0}" -f $_.Exception.Message) 'WARNING'
        }
      } else {
        Log ("Using existing MSI (age: {0:N1} days, size: {1} bytes). Skipping download." -f $age.TotalDays, $fi.Length)
        $reuse = $true
      }
    } else {
      Log ("Existing MSI is too old or too small (age: {0:N1} days, size: {1} bytes). Re-downloading." -f $age.TotalDays, $fi.Length)
    }
  }
  if ($reuse) { return }

  Log ("Downloading MSI: {0}" -f $DownloadUrl)
  try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if ([enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls13') {
      [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls13
    }
  } catch {}

  $ProgressPreference = 'SilentlyContinue'
  Invoke-WebRequest -Uri $DownloadUrl -OutFile $OutFile -UseBasicParsing -Headers @{ 'User-Agent'='WS1-Refit/1.0' }

  if (-not (Test-Path $OutFile)) { throw "Download failed: $OutFile not found" }
  $size = (Get-Item $OutFile).Length
  if ($size -lt 100000) { throw "Downloaded MSI seems too small ($size bytes)" }
  Log ("Saved to {0} ({1} bytes)" -f $OutFile, $size)

  if ($Sha256) {
    Log "Verifying SHA-256..."
    $actual = (Get-FileHash -Algorithm SHA256 -Path $OutFile).Hash.ToLowerInvariant()
    if ($actual -ne $Sha256.ToLowerInvariant()) {
      Log ("SHA-256 mismatch. Expected {0}, got {1}" -f $Sha256, $actual) 'ERROR'
      throw "Checksum verification failed."
    }
    Log "Checksum OK."
  }
}

# ---------- Stage 3: Secure install via Windows Installer COM ----------
function Invoke-InstallWithRetry {
  param(
    [ScriptBlock]$DoInstall,
    [int]$Retries = 3,
    [int]$DelaySec = 20
  )
  for ($i=0; $i -lt $Retries; $i++) {
    try { & $DoInstall; return } catch {
      $msg = $_.Exception.Message
      if ($msg -match '1618|another installation is in progress') {
        Log ("Install blocked (1618). Retry {0}/{1} after {2} sec..." -f ($i+1), $Retries, $DelaySec) 'WARNING'
        Start-Sleep -Seconds $DelaySec
        continue
      }
      throw
    }
  }
  throw "Install failed after retries (likely 1618)."
}

function Install-Ws1AgentSecure {
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory)][string]$MsiPath,
    [string]$Server,
    [string]$GroupID,
    [string]$Username,
    [securestring]$Password
  )

  if (-not (Test-Path -LiteralPath $MsiPath)) { throw "MSI not found at: $MsiPath" }
  $msiLen = (Get-Item -LiteralPath $MsiPath).Length
  if ($msiLen -lt 1024) { throw "MSI at $MsiPath looks too small ($msiLen bytes)" }

  # Build MSI properties safely
  $propsList = @(
    "ENROLL=$Enroll",
    'IMAGE=N',
    "ASSIGNTOLOGGEDINUSER=$AssignToLoggedInUser",
    'REBOOT=ReallySuppress'
  )
  if ($Server  -and $Server.Trim())  { $propsList += "SERVER=$($Server.Trim())" }
  if ($GroupID -and $GroupID.Trim()) { $propsList += "LGName=$($GroupID.Trim())" }

  $bstr = [IntPtr]::Zero
  $plainPwd = $null
  if ($Username -and $Username.Trim()) {
    $propsList += "USERNAME=$($Username.Trim())"
    if ($Password) {
      $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
      $plainPwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
      if ($plainPwd -and $plainPwd.Trim()) { $propsList += "PASSWORD=$plainPwd" }
    }
  }

  $props = [string]($propsList -join ' ').Trim()
  if ([string]::IsNullOrWhiteSpace($props)) { throw "Computed MSI property string is empty." }

  $resolvedMsi = [string](Resolve-Path -LiteralPath $MsiPath).ProviderPath
  $debugProps = ($props -replace 'PASSWORD=[^\s]+', 'PASSWORD=****')
  Log ("DEBUG: MsiPath={0}" -f $resolvedMsi)
  Log ("DEBUG: Props={0}" -f $debugProps)

  # Ensure Windows Installer is idle before attempting install (8-minute cap)
  Log ("Waiting for Windows Installer to be idle before install... (timeout: {0}s ≈ {1} min)" -f 480, [math]::Round(480/60.0,1))
  [void](Wait-ForInstallerIdle -TimeoutSec 480)

  try {
    $global:__msiLogPath = $null
    if ($EnableMsiLogging) {
      $global:__msiLogPath = Join-Path $env:TEMP ("AirwatchAgent_install_{0}.log" -f (Get-Date).ToString('yyyyMMdd_HHmmss'))
    }

    $logMask = if ($MsiLogLevel -eq 'Verbose') { 1023 } else { 7 }

    if ($PSCmdlet.ShouldProcess("AirWatch Agent MSI","Install via COM (STA) with passive UI")) {
      Log "Starting secure install via Windows Installer COM (STA)"

      Invoke-InstallWithRetry -DoInstall {
        $rs = [runspacefactory]::CreateRunspace()
        $rs.ApartmentState = 'STA'
        $rs.Open()
        try {
          $ps = [PowerShell]::Create()
          $ps.Runspace = $rs

          $script = @'
param($msiPathParam, $propsParam, $enableLog, $logPath, $logMask)
$installer = New-Object -ComObject WindowsInstaller.Installer
$installer.UILevel = 67
if ($enableLog -and $logPath) {
  try { $installer.EnableLog($logMask, $logPath, 0) | Out-Null } catch {}
}
$installer.InstallProduct([string]$msiPathParam, [string]$propsParam)
'@

          $null = (
            $ps.AddScript($script, $true).
               AddArgument($resolvedMsi).
               AddArgument($props).
               AddArgument([bool]$EnableMsiLogging).
               AddArgument($global:__msiLogPath).
               AddArgument($logMask)
          )

          $ps.Invoke() | Out-Null
          if ($ps.HadErrors) {
            $errs = ($ps.Streams.Error | ForEach-Object { $_.ToString() }) -join '; '
            throw ("Install via COM reported errors: {0}" -f $errs)
          }
        }
        finally {
          $rs.Close()
        }
      }

      if ($EnableMsiLogging -and $global:__msiLogPath) {
        Log ("MSI logging enabled at: {0} (level: {1})" -f $global:__msiLogPath, $MsiLogLevel)
      }
      Log "InstallProduct completed (no COM exception). Verify Hub presence / event logs." 'SUCCESS'
    }
  }
  catch {
    Log ("Install failed: {0}" -f $_.Exception.Message) 'ERROR'
    throw
  }
  finally {
    if ($plainPwd) { [System.Array]::Clear([char[]]$plainPwd, 0, $plainPwd.Length) | Out-Null }
    if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
  }
}

# ---------- Stage 4: Launch Hub ----------
function Start-WS1Hub {
  [CmdletBinding()]
  param([int]$WaitSeconds = 30)

  function Invoke-NonElevated($path, $args='') {
    try {
      $shell = New-Object -ComObject Shell.Application
      Log ("Launching non-elevated via ShellExecute: {0} {1}" -f $path, $args)
      $shell.ShellExecute($path, $args, $null, 'open', 1) | Out-Null
      return $true
    } catch {
      Log ("ShellExecute failed: {0}. Falling back to Start-Process (may be elevated)." -f $_.Exception.Message) 'WARNING'
      try { Start-Process -FilePath $path -ArgumentList $args | Out-Null; return $true } catch { Log ("Fallback launch failed: {0}" -f $_.Exception.Message) 'ERROR' }
    }
    return $false
  }

  $classicRoots = @(
    "$env:ProgramFiles(x86)\Workspace ONE\Intelligent Hub",
    "$env:ProgramFiles\Workspace ONE\Intelligent Hub",
    "$env:ProgramFiles(x86)\Airwatch\AgentUI",
    "$env:ProgramFiles\Airwatch\AgentUI"
  ) | Where-Object { Test-Path $_ }

  $preferredExeNames = @('AW.Win32.ModernApp.exe','NativeEnrollment.exe','Hub.exe','AgentUI.exe')

  $sw = [Diagnostics.Stopwatch]::StartNew()
  $exe = $null
  while ($sw.Elapsed.TotalSeconds -lt $WaitSeconds -and -not $exe) {
    $candidates = foreach ($r in $classicRoots) {
      foreach ($n in $preferredExeNames) {
        $p = Join-Path $r $n
        if (Test-Path $p) { $p }
      }
    }
    $candidates = $candidates | Select-Object -Unique

    $exe = $candidates | Select-Object -First 1
    if (-not $exe) { Start-Sleep -Milliseconds 400 }
  }
  if ($exe) {
    if (Invoke-NonElevated $exe) { Log ("Launched Hub classic EXE: {0}" -f $exe) 'SUCCESS' }
    return
  }

  try {
    $pkg = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
           Where-Object { $_.Name -match '(?i)(WorkspaceONEIntelligentHub|IntelligentHub|AirWatchLLC\.WorkspaceONE)' } |
           Select-Object -First 1
    if ($pkg) {
      $pfn = $pkg.PackageFamilyName
      $appIds = @('App','WorkspaceONE.IntelligentHub.App.WinUI','Hub','Main')

      $shell  = New-Object -ComObject Shell.Application
      $folder = $shell.Namespace('shell:AppsFolder')

      foreach ($appid in $appIds) {
        $aumid = "$pfn!$appid"
        $moniker = "shell:AppsFolder\$aumid"
        try {
          Log ("Trying UWP ShellExecute: {0}" -f $moniker)
          $shell.ShellExecute($moniker) | Out-Null
          Log ("Launched Hub via UWP AUMID: {0}" -f $aumid) 'SUCCESS'
          return
        } catch {
          try {
            $item = $folder.Items() | Where-Object { $_.Path -eq $aumid } | Select-Object -First 1
            if ($item) {
              Log ("Invoking AppsFolder item (AUMID): {0}" -f $aumid)
              $item.InvokeVerb('open')
              Log ("Launched Hub via AppsFolder AUMID: {0}" -f $aumid) 'SUCCESS'
              return
            }
          } catch { }
        }
      }
    }
  } catch {
    Log ("UWP launch error: {0}" -f $_.Exception.Message) 'WARNING'
  }
}

# ---------- Main ----------
Test-Admin
Log "=== WS1 Reinstall Orchestrator (COM) started ==="

function Read-BoxedPrompt {
    param(
        [string]$Title,
        [string]$Subtext = "",
        [string]$Prompt,
        [switch]$Secure
    )

    $boxWidth = 60

    $borderColor = "DarkCyan"
    $titleColor  = "Yellow"
    $warnColor   = "Red"

    Write-Host ""
    Write-Host ("*" * ($boxWidth + 6)) -ForegroundColor $borderColor

    # Title line
    $titleLine = ("*   {0}*" -f $Title.PadRight($boxWidth))
    Write-Host $titleLine -ForegroundColor $titleColor -BackgroundColor DarkBlue

    # Subtext line(s)
    if ($Subtext) {
        $wrapped = $Subtext -split "(.{1,$boxWidth})(\s+|$)" | Where-Object { $_ -and $_ -notmatch '^\s+$' }
        foreach ($line in $wrapped) {
            $out = ("*   {0}*" -f $line.PadRight($boxWidth))
            Write-Host $out -ForegroundColor $warnColor
        }
    }

    Write-Host ("*" * ($boxWidth + 6)) -ForegroundColor $borderColor
    Write-Host ""

    if ($Secure) { return Read-Host $Prompt -AsSecureString } else { return Read-Host $Prompt }
}

try {
  if ($PSCmdlet.ShouldProcess("Workspace ONE Agent", "Backup+Uninstall, then Download+Secure Install")) {
    Invoke-BackupAndUninstall
    Save-WS1AgentInstaller -MaxAgeDays $MaxAgeDays

    $srv   = $Server
    $grp   = $GroupID
    $user  = $Username
    $pwd   = $Password

    $isInteractive = -not $NonInteractive.IsPresent -and $Host.Name -notin 'ServerRemoteHost'

    if ($isInteractive -and (-not $Server -and -not $GroupID -and -not $Username)) {
      $choice = Read-BoxedPrompt -Title "Do you want to enter enrollment details?" `
                                 -Subtext "(Y = Yes, N = No; use N if PingID is needed for enrollment)" `
                                 -Prompt "Select option (Y/N):"

      if ($choice -match '^(?i)y') {
        $srv  = Read-BoxedPrompt -Title "Enter Workspace ONE UEM Server URL" `
                                 -Subtext "(Leave blank to skip)" `
                                 -Prompt "Server URL"

        $grp  = Read-BoxedPrompt -Title "Enter Organization Group ID (LGName)" `
                                 -Subtext "(Leave blank to skip)" `
                                 -Prompt "Group ID"

        $user = Read-BoxedPrompt -Title "Enter Staging Username" `
                                 -Subtext "(Leave blank to skip)" `
                                 -Prompt "Staging Username"

        if ($user) {
          $pwd = Read-BoxedPrompt -Title "Enter Staging Password" `
                                  -Subtext "(Leave blank to skip)" `
                                  -Prompt "Staging Password" -Secure
        }
      } else {
        Log "User chose to leave all enrollment details blank."
      }
    }

    Log ("Waiting for Windows Installer to be idle before starting install... (timeout: {0}s ≈ {1} min)" -f 480, [math]::Round(480/60.0,1))
    if (Wait-ForInstallerIdle -TimeoutSec 480 -PollMs 2000) {
      Log "Windows Installer is idle." 'SUCCESS'
    } else {
      Log "Continuing despite possible installer activity (install may fail)." 'WARNING'
    }

    Install-Ws1AgentSecure -MsiPath $OutFile -Server $srv -GroupID $grp -Username $user -Password $pwd

    Start-WS1Hub
    Log "=== All stages finished ===" 'SUCCESS'
    Write-Host ""
    Write-Host ("Done. Stage log: {0}" -f $LogFile) -ForegroundColor Green
    Write-Host ""
  }
}
catch {
  Log ("FATAL: {0}" -f $_.Exception.Message) 'ERROR'
  Write-Error $_
  exit 1
}
finally {
  try { Stop-Transcript | Out-Null } catch {}
}
