<#
.SYNOPSIS
    Automates backup, removal, and reinstallation of Omnissa Workspace ONE / AirWatch Agent.

.DESCRIPTION
    This script provides a controlled process for fully uninstalling the Workspace ONE Intelligent Hub 
    (formerly AirWatch Agent), backing up related registry data, cleaning residual components, and 
    reinstalling the agent via MSI with secure COM-based installation.

    The workflow is divided into four stages:
      1. Backup & Uninstall – Stops services, backs up registry keys, uninstalls Hub/Agent (MSI/EXE/AppX),
         removes leftover registry entries and device certificates.
      2. Download – Retrieves the Hub MSI installer from a given URL with optional SHA-256 verification.
      3. Secure Install – Performs installation using Windows Installer COM to avoid elevation/credential leaks,
         supporting enrollment and logging options.
      4. Launch Hub – Attempts to launch the Intelligent Hub app (classic EXE or UWP) non-elevated.

.PARAMETER DownloadUrl
    URL of the MSI package to download. Defaults to the official Omnissa distribution.

.PARAMETER OutFile
    Local file path to save the MSI. Defaults to C:\TEMP\AirwatchAgent.msi.

.PARAMETER Sha256
    Optional SHA-256 checksum to validate the downloaded MSI.

.PARAMETER Enroll
    Whether to enable enrollment (Y/N). Defaults to N.

.PARAMETER AssignToLoggedInUser
    Whether to auto-assign the agent to the currently logged-in user (Y/N). Defaults to N.

.PARAMETER EnableMsiLogging
    Switch to enable detailed MSI logging during installation.

.PARAMETER MsiLogLevel
    MSI logging verbosity. Options: Minimal, Verbose. Defaults to Verbose.

.PARAMETER MaxAgeDays
    Maximum age (in days) for a cached MSI file before forcing a re-download. Defaults to 7.

.PARAMETER Server
    Workspace ONE UEM server URL (optional).

.PARAMETER GroupID
    Organization Group ID (LGName) for enrollment (optional).

.PARAMETER Username
    Staging or enrollment username (optional).

.PARAMETER Password
    Secure password for enrollment (optional, masked in logs).

.PARAMETER NonInteractive
    Switch to bypass all interactive prompts (useful for automation/remote execution).

.NOTES
    - Must be run as Administrator.
    - Generates a detailed log file in %ProgramData%.
    - Uses ShouldProcess for safe WhatIf support.
    - Designed for enterprise deployment, recovery, or remediation scenarios.

.EXAMPLE
    .\WS1-ReEnrollment.ps1 -DownloadUrl "https://packages.omnissa.com/wsone/AirwatchAgent.msi" `
                       -Enroll Y -AssignToLoggedInUser Y -EnableMsiLogging

    Downloads the latest agent, uninstalls any existing installation, then reinstalls and enrolls
    the device, with verbose MSI logging enabled.

.AUTHOR
    James Romeo Gaspar
    Version: 1.0
    Date: August 28, 2025
#>


[CmdletBinding(SupportsShouldProcess)]
param(
  [string]$DownloadUrl = "https://packages.omnissa.com/wsone/AirwatchAgent.msi",
  [string]$OutFile     = "C:\TEMP\AirwatchAgent.msi",
  [string]$Sha256,                          # optional integrity check
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
$LogFile = "$env:ProgramData\ws1_backup_uninstall_$DateNow.log"
function Log { param([string]$m,[string]$lvl='INFO')
  $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  "$ts`t($lvl)`t$m" | Tee-Object -FilePath $LogFile -Append
}
try { Start-Transcript -Path (Join-Path $env:ProgramData "ws1_backup_uninstall_$DateNow.trn") -ErrorAction SilentlyContinue } catch {}

# ---------- Helpers ----------
function Ensure-Admin {
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).
             IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
  if (-not $isAdmin) {
    Write-Host "This script must be run as Administrator." -ForegroundColor Red
    exit 1
  }
}

function Split-CmdLine([string]$s) {
  if ($s -match '^\s*"([^"]+)"\s*(.*)$') { return ,$Matches[1],$Matches[2] }
  elseif ($s -match '^\s*(\S+)\s*(.*)$') { return ,$Matches[1],$Matches[2] }
  else { return ,$s,'' }
}

# ---------- Stage 1: Backup + Uninstall ----------
function Stage-BackupAndUninstall {
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

      $dnProp = $ip.PSObject.Properties['DisplayName']
      $unProp = $ip.PSObject.Properties['UninstallString']
      $quProp = $ip.PSObject.Properties['QuietUninstallString']

      $dn = if ($dnProp) { $dnProp.Value } else { $null }
      $un = if ($unProp) { $unProp.Value } else { $null }
      $qu = if ($quProp) { $quProp.Value } else { $null }

      if ($dn -and ($un -or $qu) -and $dn -match $patterns) {
        [pscustomobject]@{
          DisplayName          = $dn
          UninstallString      = $un
          QuietUninstallString = $qu
        }
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
    $cmd,$args = if ($QuietUninstallString) { Split-CmdLine $QuietUninstallString } else { Split-CmdLine $UninstallString }
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
  try {
    Invoke-Uninstall -DisplayName $p.DisplayName -UninstallString $p.UninstallString -QuietUninstallString $p.QuietUninstallString
  } catch {
    Log "Uninstall dispatch warn for ${($p.DisplayName -as [string])}: $($_.Exception.Message)" 'WARNING'
  }
}


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
      }
      catch { Log "Registry cleanup warn ($rk): $($_.Exception.Message)" 'WARNING' }
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

# ---------- Stage 2: Download ----------
function Stage-Download {
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
      [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor ([Net.SecurityProtocolType]::Tls13)
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

  $props = $propsList -join ' '
  $debugProps = ($props -replace 'PASSWORD=[^\s]+', 'PASSWORD=****')
  Log "DEBUG: MsiPath=$MsiPath"
  Log "DEBUG: Props=$debugProps"

  try {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $installer.UILevel = 67

    if ($EnableMsiLogging) {
      $msiLog = Join-Path $env:TEMP "AirwatchAgent_install_$((Get-Date).ToString('yyyyMMdd_HHmmss')).log"
      $mask = if ($MsiLogLevel -eq 'Verbose') { 1023 } else { 7 }  # 1023 ~ typical verbose; 7 fatal+error+warning
      try { $installer.EnableLog($mask, $msiLog, 0) | Out-Null; Log "MSI logging enabled at: $msiLog (level: $MsiLogLevel)" } catch {}
    }

    if ($PSCmdlet.ShouldProcess("AirWatch Agent MSI","Install via COM with passive UI")) {
      Log "Starting secure install via Windows Installer COM"
      $installer.InstallProduct($MsiPath, $props)
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
Ensure-Admin
Log "=== WS1 Reinstall Orchestrator (COM) started ==="

# helper for boxed input prompts
function Show-BoxedPrompt {
    param(
        [string]$Title,
        [string]$Subtext = "",
        [string]$Prompt,
        [switch]$Secure
    )

    $borderColor = "DarkCyan"
    $titleColor  = "Yellow"
    $warnColor   = "Red"

    Write-Host ""
    Write-Host ("*" * 60) -ForegroundColor $borderColor
    Write-Host ("*   {0,-54}*" -f $Title) -ForegroundColor $titleColor -BackgroundColor DarkBlue
    if ($Subtext) {
        Write-Host ("*   {0,-54}*" -f $Subtext) -ForegroundColor $warnColor
    }
    Write-Host ("*" * 60) -ForegroundColor $borderColor
    Write-Host ""

    if ($Secure) {
        return Read-Host $Prompt -AsSecureString
    } else {
        return Read-Host $Prompt
    }
}

try {
  if ($PSCmdlet.ShouldProcess("Workspace ONE Agent", "Backup+Uninstall, then Download+Secure Install")) {
    Stage-BackupAndUninstall
    Stage-Download -MaxAgeDays $MaxAgeDays

    $srv   = $Server
    $grp   = $GroupID
    $user  = $Username
    $pwd   = $Password

    $isInteractive = -not $NonInteractive.IsPresent -and $Host.Name -notin 'ServerRemoteHost'

    if ($isInteractive -and (-not $Server -and -not $GroupID -and -not $Username)) {
      $choice = Show-BoxedPrompt -Title "Do you want to enter enrollment details?" `
                                 -Subtext "(Y = Yes, N = No; if PingID is required, choose N)" `
                                 -Prompt "Your choice"

      if ($choice -match '^(?i)y') {
        $srv  = Show-BoxedPrompt -Title "Enter Workspace ONE UEM Server URL" `
                                 -Subtext "(Leave blank to skip)" `
                                 -Prompt "Server URL"

        $grp  = Show-BoxedPrompt -Title "Enter Organization Group ID (LGName)" `
                                 -Subtext "(Leave blank to skip)" `
                                 -Prompt "Group ID"

        $user = Show-BoxedPrompt -Title "Enter Staging Username" `
                                 -Subtext "(Leave blank to skip)" `
                                 -Prompt "Staging Username"

        if ($user) {
          $pwd = Show-BoxedPrompt -Title "Enter Staging Password" `
                                  -Subtext "(Leave blank to skip)" `
                                  -Prompt "Staging Password" -Secure
        }
      } else {
        Log "User chose to leave all enrollment details blank."
      }
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
