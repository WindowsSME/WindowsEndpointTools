<#
.SYNOPSIS
    Scans Workspace ONE AppManifest registry entries and checks uninstall commands.

.DESCRIPTION
    Retrieves all app entries from the specified WS1 AppManifests registry path.
    Counts total applications and how many do NOT use "EXIT" as the uninstall CommandLine value.

.PARAMETER RegistryPath
    Registry path to scan (default: HKLM:\SOFTWARE\AirWatchMDM\AppDeploymentAgent\AppManifests)

.NOTES
    Author: James Romeo Gaspar
    Date: November 27, 2025
#>

function Get-WS1UninstallInfo {
    [CmdletBinding()]
    param(
        [string]$RegistryPath = "HKLM:\SOFTWARE\AirWatchMDM\AppDeploymentAgent\AppManifests",
        [switch]$Quiet,
        [switch]$Passthru
    )

    if (-not (Test-Path $RegistryPath)) {
        Write-Host "Registry path not found: $RegistryPath"
        return @()
    }

    $subKeys           = Get-ChildItem $RegistryPath
    $totalSubKeys      = $subKeys.Count
    $uninstallCmdFound = 0
    $nonExitCount      = 0
    $nonExitApps       = @()
    $results           = @()

    foreach ($key in $subKeys) {
        
        $regProps = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
        if (-not $regProps) { continue }

        $AppName       = $regProps.Name
        if (-not $AppName) { $AppName = $key.PSChildName }

        $manifestValue = $regProps.DeploymentManifestXML
        if (-not $manifestValue) { continue }

        $uninstallBlock = [regex]::Match(
            $manifestValue,
            '(?is)<Method\s+Id="uninstall".*?</Method>'
        ).Value
        if (-not $uninstallBlock) { continue }

        $cmdMatch = [regex]::Match(
            $uninstallBlock,
            '(?is)<Key\s+Name="CommandLine">(.*?)</Key>'
        )
        if (-not $cmdMatch.Success) { continue }

        $uninstallCmdFound++
        $commandLine = $cmdMatch.Groups[1].Value.Trim()

        $isExitCommand = $commandLine -match '^(?i)exit$'
        if (-not $isExitCommand) {
            $nonExitCount++
            $nonExitApps += $AppName
        }

        $results += [PSCustomObject]@{
            AppManifestKey   = $key.PSChildName
            AppName          = $AppName
            UninstallCommand = $commandLine
            IsExitCommand    = $isExitCommand
        }
    }

    $nonExitSummary = ""
    if ($nonExitCount -gt 0 -and $nonExitApps.Count -gt 0) {
        $nonExitSummary = " | (" + ($nonExitApps -join ', ') + ")"
    }

    if (-not $Quiet) {
        Write-Output "Total Apps: $totalSubKeys | Non-EXIT Apps: $nonExitCount$nonExitSummary"
    }

    if ($Passthru) {
        return $results
    }
}

Get-WS1UninstallInfo
