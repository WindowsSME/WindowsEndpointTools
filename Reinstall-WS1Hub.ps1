<#
.SYNOPSIS
  Workspace ONE Intelligent Hub reinstallation orchestrator.

.DESCRIPTION
  This script automates the safe removal and reinstallation of the 
  VMware/Workspace ONE Intelligent Hub (AirWatch Agent). It performs the following:
   - Ensures script is running as Administrator.
   - Logs all operations to both transcript and log file.
   - Stops Workspace ONE services and backs up deployment manifests.
   - Uninstalls existing Workspace ONE Hub/Agent (MSI/EXE and APPX).
   - Cleans up residual registry keys and device certificates.
   - Downloads the latest installer (or reuses cached MSI if valid).
   - Verifies installer integrity via SHA-256 (if provided).
   - Performs a secure reinstallation using Windows Installer COM APIs with retries.
   - Optionally provides interactive prompts for enrollment details.
   - Launches the Hub app after installation.

.PARAMETER DownloadUrl
  URL to download the Workspace ONE Hub/Agent MSI. Defaults to:
  https://packages.omnissa.com/wsone/AirwatchAgent.msi

.PARAMETER OutFile
  Local path where the MSI will be saved. Defaults to C:\Temp\AirwatchAgent.msi

.PARAMETER Sha256
  Optional SHA-256 hash for integrity verification of the MSI.

.PARAMETER Enroll
  Whether to enroll immediately after install. Accepts 'Y' or 'N'. Default: 'N'

.PARAMETER AssignToLoggedInUser
  Whether to assign enrollment to the logged-in user. Accepts 'Y' or 'N'. Default: 'N'

.PARAMETER EnableMsiLogging
  Enables detailed MSI logging during install.

.PARAMETER MsiLogLevel
  MSI logging level: 'Minimal' or 'Verbose'. Default: 'Verbose'

.PARAMETER MaxAgeDays
  Maximum age (in days) to reuse an existing downloaded MSI before re-downloading.
  Default: 7

.PARAMETER Server
  Workspace ONE UEM server URL (if enrolling).

.PARAMETER GroupID
  Organization Group ID (LGName) used during enrollment.

.PARAMETER Username
  Staging username for enrollment.

.PARAMETER Password
  Secure string password for staging user (if Username is provided).

.PARAMETER NonInteractive
  Skip interactive enrollment prompts (for automated use).

.NOTES
  Author: James Romeo Gaspar
  Date: August 29, 2025

  Requirements:
    - Must be run with elevated Administrator privileges.
    - Requires PowerShell 5.1+.

.EXAMPLE
  .\Reinstall-WS1Hub.ps1 -DownloadUrl "https://packages.omnissa.com/wsone/AirwatchAgent.msi" `
                         -OutFile "C:\Temp\AirwatchAgent.msi" `
                         -Sha256 "abcdef123456..." `
                         -Enroll Y -AssignToLoggedInUser N -EnableMsiLogging `
                         -Server "https://uem.mycompany.com" `
                         -GroupID "Production" `
                         -Username "staginguser"

  Removes any existing Workspace ONE Intelligent Hub, cleans up environment, 
  downloads and verifies the installer, and securely reinstalls with enrollment.
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
  [switch]$NonInteractive
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
try { Start-Transcript -Path (Join-Path $env:ProgramData "ws1_backup_uninstall_$DateNow.trn") -ErrorAction SilentlyContinue } catch {}

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

# --- WS1 uninstall detection + wait ---
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


function Wait-UntilUninstalled {
  param([int]$TimeoutSec = 900, [int]$PollMs = 1000)
  $sw = [Diagnostics.Stopwatch]::StartNew()
  do {
    $remaining = Get-Ws1UninstallEntries
    if (-not $remaining -or $remaining.Count -eq 0) { return $true }
    Start-Sleep -Milliseconds $PollMs
  } while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec)
  Log ("Timeout waiting for uninstall. Still present: {0}" -f ($remaining -join ', ')) 'WARNING'
  return $false
}

# --- Windows Installer idle wait ---
function Wait-ForInstallerIdle {
  param([int]$TimeoutSec = 900, [int]$PollMs = 1000)
  $sw = [Diagnostics.Stopwatch]::StartNew()
  do {
   $msiBusy = Get-Process msiexec -ErrorAction SilentlyContinue
   $inProgress = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\InProgress'
   if (-not $msiBusy -and -not $inProgress) { return $true }
   Start-Sleep -Milliseconds $PollMs
  } while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec)
  Log "Windows Installer still busy after timeout." 'WARNING'
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
      } catch { Log "Service stop warn ($svcName): $($_.Exception.Message)" 'WARNING' }
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
              Log "Backed up DeploymentManifestXML for $app"
            }
          }
        } catch { Log "Manifest backup warn for ${app}: $($_.Exception.Message)" 'WARNING' }
      }
    } catch { Log "Manifest enumeration warn: $($_.Exception.Message)" 'WARNING' }

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
          Log "Uninstall key read warn $($_.PsPath): $($_.Exception.Message)" 'WARNING'
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
          Log "Skip ${DisplayName}: no uninstall strings" 'WARNING'
          return
        }
        $cmd,$args = if ($QuietUninstallString) { ConvertFrom-CmdLine $QuietUninstallString } else { ConvertFrom-CmdLine $UninstallString }
        if (-not $cmd) { Log "Skip ${DisplayName}: parsed empty command" 'WARNING'; return }

        if ($cmd -match '(?i)msiexec(\.exe)?$' -and $args -match '/X\s*({[^}]+})') {
          $alist = @('/X', $Matches[1], '/qn', 'REBOOT=ReallySuppress')
          Log "Running msiexec $($alist -join ' ') for ${DisplayName}"
          if ($PSCmdlet.ShouldProcess($DisplayName,"msiexec /X")) {
            $code = (Start-Process msiexec.exe -ArgumentList $alist -PassThru -Wait).ExitCode
            Log "Uninstall of ${DisplayName} exit code: $code"
          }
        } elseif ($cmd -match '(?i)\.(exe|cmd|bat)$') {
          if ($PSCmdlet.ShouldProcess($DisplayName,"$cmd $args")) {
            Log "Running quiet uninstall: $cmd $args for ${DisplayName}"
            $code = (Start-Process $cmd -ArgumentList $args -PassThru -Wait).ExitCode
            Log "Uninstall of ${DisplayName} exit code: $code"
          }
        } else {
          if ($args -match '({[^}]+})') {
            if ($PSCmdlet.ShouldProcess($DisplayName,"msiexec /X {GUID}")) {
              $code = (Start-Process msiexec.exe -ArgumentList '/X',$Matches[1],'/qn','REBOOT=ReallySuppress' -PassThru -Wait).ExitCode
              Log "Uninstall of ${DisplayName} exit code: $code"
            }
          } else {
            Log "Unknown uninstall format for ${DisplayName}: $cmd $args" 'WARNING'
          }
        }
      } catch {
        Log "Uninstall error for ${DisplayName}: $($_.Exception.Message)" 'WARNING'
      }
    }

    foreach ($p in $products) {
      try { Invoke-Uninstall -DisplayName $p.DisplayName -UninstallString $p.UninstallString -QuietUninstallString $p.QuietUninstallString }
      catch { Log "Uninstall dispatch warn for ${($p.DisplayName -as [string])}: $($_.Exception.Message)" 'WARNING' }
    }

    Log "Verifying products are removed..."
    [void](Wait-UntilUninstalled -TimeoutSec 900)

    Log "Waiting for Windows Installer to be idle..."
    [void](Wait-ForInstallerIdle -TimeoutSec 900)

    Log "Removing Workspace ONE Hub APPX for all users"
    try {
      Get-AppxPackage -AllUsers -Name '*AirwatchLLC*' -ErrorAction SilentlyContinue | ForEach-Object {
        try {
          if ($PSCmdlet.ShouldProcess($_.PackageFullName,"Remove-AppxPackage -AllUsers")) {
            Log "Remove-AppxPackage -AllUsers $($_.PackageFullName)"
            Remove-AppxPackage -AllUsers -Package $_.PackageFullName -Confirm:$false -ErrorAction Stop
          }
        } catch { Log "APPX removal warn ($($_.PackageFullName)): $($_.Exception.Message)" 'WARNING' }
      }
    } catch { Log "APPX enumeration warn: $($_.Exception.Message)" 'WARNING' }

    Log "Cleaning residual registry keys"
    foreach ($rk in @(
      'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\AirWatch',
      'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\AirWatchMDM'
    )) {
      try {
        if ($PSCmdlet.ShouldProcess($rk, "Remove-Item -Recurse -Force")) {
          Remove-Item -Path $rk -Recurse -Force -ErrorAction Stop
          Log "Removed $rk"
        }
      } catch { Log "Registry cleanup warn ($rk): $($_.Exception.Message)" 'WARNING' }
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
                  Log "Removing cert from ${storePath}: $($_.Subject)"
                  Remove-Item -Path $_.PSPath -Force -ErrorAction Stop
                }
              } catch {
                Log "Cert removal warn ($($_.Subject) in $storePath): $($_.Exception.Message)" 'WARNING'
              }
            }
        } catch {
          Log "Cert store access warn ($storePath): $($_.Exception.Message)" 'WARNING'
        }
      }
    }

    Log "Backup + uninstall stage complete" 'SUCCESS'
    Log "Log file: $LogFile"
  }
  catch {
    Log "ERROR: $($_.Exception.Message)" 'ERROR'
    throw
  }
}

function Wait-ForInstallerIdle {
  param([int]$TimeoutSec = 900, [int]$PollMs = 2000)
  $sw = [Diagnostics.Stopwatch]::StartNew()
  do {
    $msiBusy = Get-Process msiexec -ErrorAction SilentlyContinue
    $inProgressKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\InProgress'
    $inProgress = Test-Path $inProgressKey

    if (-not $msiBusy -and -not $inProgress) { return $true }

    Log "Windows Installer busy... still waiting (elapsed: {0:N0}s)" -f $sw.Elapsed.TotalSeconds
    Start-Sleep -Milliseconds $PollMs
  } while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec)

  Log "Windows Installer still busy after $TimeoutSec seconds." 'WARNING'
  return $false
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
            Log "Existing MSI hash mismatch (expected $Sha256, got $actual). Re-downloading." 'WARNING'
          }
        } catch {
          Log "Failed to hash existing MSI. Re-downloading. Error: $($_.Exception.Message)" 'WARNING'
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

  Log "Downloading MSI: $DownloadUrl"
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
  Log "Saved to $OutFile ($size bytes)"

  if ($Sha256) {
    Log "Verifying SHA-256..."
    $actual = (Get-FileHash -Algorithm SHA256 -Path $OutFile).Hash.ToLowerInvariant()
    if ($actual -ne $Sha256.ToLowerInvariant()) {
      Log "SHA-256 mismatch. Expected $Sha256, got $actual" 'ERROR'
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
        Log "Install blocked (1618). Retry $($i+1)/$Retries after $DelaySec sec..." 'WARNING'
        Start-Sleep -Seconds $DelaySec
        continue
      }
      throw
    }
  }
  throw "Install failed after $Retries retries (likely 1618)."
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
  Log "DEBUG: MsiPath=$resolvedMsi"
  Log "DEBUG: Props=$debugProps"

  # Ensure Windows Installer is idle before attempting install (8-minute cap)
  Log "Waiting for Windows Installer to be idle before install..."
  [void](Wait-ForInstallerIdle -TimeoutSec 480)

  try {
    $global:__msiLogPath = $null
    if ($EnableMsiLogging) {
      $global:__msiLogPath = Join-Path $env:TEMP "AirwatchAgent_install_$((Get-Date).ToString('yyyyMMdd_HHmmss')).log"
    }
    # Compute log mask BEFORE the AddArgument chain (avoid 'if' inside AddArgument)
    $logMask = if ($MsiLogLevel -eq 'Verbose') { 1023 } else { 7 }

    if ($PSCmdlet.ShouldProcess("AirWatch Agent MSI","Install via COM (STA) with passive UI")) {
      Log "Starting secure install via Windows Installer COM (STA)"

      Invoke-InstallWithRetry -DoInstall {
        # Create STA runspace just for the COM call
        $rs = [runspacefactory]::CreateRunspace()
        $rs.ApartmentState = 'STA'
        $rs.Open()
        try {
          $ps = [PowerShell]::Create()
          $ps.Runspace = $rs

          # Use a here-string for maximum compatibility
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
            throw "Install via COM reported errors: $errs"
          }
        }
        finally {
          $rs.Close()
        }
      }

      if ($EnableMsiLogging -and $global:__msiLogPath) {
        Log "MSI logging enabled at: $global:__msiLogPath (level: $MsiLogLevel)"
      }
      Log "InstallProduct completed (no COM exception). Verify Hub presence / event logs." 'SUCCESS'
    }
  }
  catch {
    Log "Install failed: $($_.Exception.Message)" 'ERROR'
    throw
  }
  finally {
    if ($plainPwd) { [System.Array]::Clear([char[]]$plainPwd, 0, $plainPwd.Length) | Out-Null }
    if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
  }
}


# ---------- Stage 4: Launch Hub  ----------
function Start-WS1Hub {
  [CmdletBinding()]
  param([int]$WaitSeconds = 30)

  function Invoke-NonElevated($path, $args='') {
    try {
      $shell = New-Object -ComObject Shell.Application
      Log "Launching non-elevated via ShellExecute: $path $args"
      $shell.ShellExecute($path, $args, $null, 'open', 1) | Out-Null
      return $true
    } catch {
      Log "ShellExecute failed: $($_.Exception.Message). Falling back to Start-Process (may be elevated)." 'WARNING'
      try { Start-Process -FilePath $path -ArgumentList $args | Out-Null; return $true } catch { Log "Fallback launch failed: $($_.Exception.Message)" 'ERROR' }
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
    if (Invoke-NonElevated $exe) { Log "Launched Hub classic EXE: $exe" 'SUCCESS' }
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
          Log "Trying UWP ShellExecute: $moniker"
          $shell.ShellExecute($moniker) | Out-Null
          Log "Launched Hub via UWP AUMID: $aumid" 'SUCCESS'
          return
        } catch {
          try {
            $item = $folder.Items() | Where-Object { $_.Path -eq $aumid } | Select-Object -First 1
            if ($item) {
              Log "Invoking AppsFolder item (AUMID): $aumid"
              $item.InvokeVerb('open')
              Log "Launched Hub via AppsFolder AUMID: $aumid" 'SUCCESS'
              return
            }
          } catch { }
        }
      }
    }
  } catch {
    Log "UWP launch error: $($_.Exception.Message)" 'WARNING'
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

    $boxWidth = 60   # inner width (between the *s)

    $borderColor = "DarkCyan"
    $titleColor  = "Yellow"
    $warnColor   = "Red"

    Write-Host ""
    Write-Host ("*" * ($boxWidth + 6)) -ForegroundColor $borderColor

    # Title line
    $titleLine = ("*   {0}*" -f $Title.PadRight($boxWidth))
    Write-Host $titleLine -ForegroundColor $titleColor -BackgroundColor DarkBlue

    # Subtext line(s) — wrap if needed
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

    # Safety Check: Ensure Installer is idle right before install
    Log "Waiting for Windows Installer to be idle before starting install..."
    if (Wait-ForInstallerIdle -TimeoutSec 480) {
        Log "Windows Installer is idle." 'SUCCESS'
    } else {
        Log "Continuing despite possible installer activity (install may fail)." 'WARNING'
    }

    Install-Ws1AgentSecure -MsiPath $OutFile -Server $srv -GroupID $grp -Username $user -Password $pwd


    Start-WS1Hub
    Log "=== All stages finished ===" 'SUCCESS'
    Write-Host ""
    Write-Host "Done. Stage log: $LogFile" -ForegroundColor Green
    Write-Host ""
  }
}
catch {
  Log "FATAL: $($_.Exception.Message)" 'ERROR'
  Write-Error $_
  exit 1
}
finally {
  try { Stop-Transcript | Out-Null } catch {}
}
