<#
.SYNOPSIS
    Hardware and User Info Report Script

.DESCRIPTION
    - Collects and summarizes key system information including:
    - Computer type (Laptop/Desktop)
    - Monitor count with descriptive wording
    - System model and serial number
    - CPU details (model, cores, threads)
    - Installed RAM size, module count, and configuration
    - Logged in username and NTID

    Output is printed in a single-line summary, with optional CSV export.

    Monitor description rules:
      - Laptop with 1 monitor  : "1 (built-in)"
      - Laptop with >1 monitors: "N (built-in, ext)"
      - Desktop with 1 monitor : "1"
      - Desktop with >1 monitors: "N"

.AUTHOR
      James Romeo Gaspar
      1.0
      August 8. 2025

#>

# --- Data Collection Functions ---

# --- Function to determine if the system is a Laptop or Desktop ---

function Get-ComputerType {
    $laptopTypes = 8,9,10,14,30,31,32
    try { $chassis = (Get-CimInstance -ClassName Win32_SystemEnclosure).ChassisTypes }
    catch { $chassis = (Get-WmiObject -Class Win32_SystemEnclosure).ChassisTypes }
    $chassis = @($chassis)
    $match = $chassis | Where-Object { $laptopTypes -contains $_ } | Select-Object -First 1
    if ($null -ne $match) { 'Laptop' } else { 'Desktop' }
}

# --- Function that returns number of monitors detected ---

function Get-MonitorCount {
    try { @(Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorID).Count }
    catch { @(Get-WmiObject -Namespace root\wmi -Class WmiMonitorID).Count }
}

# --- Function to get the system model name ---

function Get-SystemModel {
    try { (Get-CimInstance -ClassName Win32_ComputerSystem).Model }
    catch { (Get-WmiObject -Class Win32_ComputerSystem).Model }
}

# --- Function to get the serial number ---

function Get-SystemSerialNumber {
    try { (Get-CimInstance -ClassName Win32_BIOS).SerialNumber }
    catch { (Get-WmiObject -Class Win32_BIOS).SerialNumber }
}

# --- Function to get the currently logged in username (with fallback) ---

function Get-Username {

    try {
        $consoleUser = (Get-CimInstance -ClassName Win32_ComputerSystem).UserName
        if (-not [string]::IsNullOrWhiteSpace($consoleUser)) {
            return ($consoleUser -split '\\')[-1]
        }
    } catch {}

    try {
        $explorer = Get-CimInstance Win32_Process -Filter "name='explorer.exe'" -ErrorAction SilentlyContinue |
                    Select-Object -First 1
        if ($explorer) {
            $owner = Invoke-CimMethod -InputObject $explorer -MethodName GetOwner
            if ($owner.ReturnValue -eq 0 -and -not [string]::IsNullOrWhiteSpace($owner.User)) {
                return $owner.User
            }
        }
    } catch {}

    try {
        $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI'
        $props   = Get-ItemProperty -Path $regPath -ErrorAction Stop
        $raw     = $props.LastLoggedOnUser
        if (-not [string]::IsNullOrWhiteSpace($raw)) {
            if ($raw -like '*@*') {
                return ($raw -split '@')[0]
            } else {
                return ($raw -split '\\', 2)[-1]
            }
        }
    } catch {}

    $tm = $env:USERNAME
    if ([string]::IsNullOrWhiteSpace($tm)) {
        try { $tm = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split '\\')[-1] } catch {}
    }

    if ($tm -match '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$' -or $tm -match '\$$') {
        return ''
    }

    return $tm
}


# --- Function to get the installed RAM (GB) ---

function Get-InstalledRAMGB {
    try { $mem = Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum }
    catch { $mem = Get-WmiObject -Class Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum }
    [math]::Round(($mem.Sum / 1GB), 2)
}

# --- Function to get CPU details ---

function Get-ProcessorDetails {
    try { $cpu = Get-CimInstance -ClassName Win32_Processor }
    catch { $cpu = Get-WmiObject -Class Win32_Processor }
    @{
        Name    = $cpu.Name
        Cores   = $cpu.NumberOfCores
        Threads = $cpu.NumberOfLogicalProcessors
    }
}

# --- Function to simplify CPU Model ---

function ConvertTo-CPUModel {
    param([string]$Name)
    if ($Name -match 'Intel\(R\).*Core\(TM\)') {
        return ($Name -replace '.*Intel\(R\)\s*Core\(TM\)\s*', '' -replace '\s*@.*', '')
    } else {
        return ($Name -replace '\s*@.*', '')
    }
}


# --- Function to get monitor setup details ---

function Get-MonitorSetupDescription {
    $type  = Get-ComputerType
    $count = Get-MonitorCount
    if ($type -eq 'Laptop') {
        if ($count -eq 1) { "1 (built-in)" }
        else { "$count (built-in, ext)" }
    } else {
        "$count"
    }
}

# --- Function to get the total number of physical RAM modules installed ---

function Get-RAMModuleCount {
    try { @(Get-CimInstance -ClassName Win32_PhysicalMemory).Count }
    catch { @(Get-WmiObject -Class Win32_PhysicalMemory).Count }
}

# --- Function to output the friendly name of the manufacturer ---

function Get-FriendlyManufacturer {
    [CmdletBinding()]
    param(
        [string]$Raw,
        [hashtable]$AdditionalMap
    )
    if ([string]::IsNullOrWhiteSpace($Raw)) { return '' }

    # Already looks like a brand? normalize and return
    if ($Raw -match '[A-Za-z]' -and $Raw -notmatch '^[0-9A-Fa-f]+$') {
        return ($Raw -replace '\s+', ' ').Trim()
    }

    # Common JEP-106 last-byte → brand (extend as you discover more)
    $map = @{
        'CE' = 'Samsung'
        'AD' = 'SK Hynix'
        '2C' = 'Micron'
        '98' = 'Kingston'
    }
    if ($AdditionalMap) { foreach ($k in $AdditionalMap.Keys) { $map[$k.ToUpper()] = $AdditionalMap[$k] } }

    # Extract hex pairs; ignore 7F/00; take LAST non-7F byte
    $pairs = ($Raw -replace '[^0-9A-Fa-f]', '').ToUpper() -split '([0-9A-F]{2})' |
             Where-Object { $_ -match '^[0-9A-F]{2}$' }
    $code  = ($pairs | Where-Object { $_ -ne '7F' -and $_ -ne '00' } | Select-Object -Last 1)

    if ($code -and $map.ContainsKey($code)) { return $map[$code] }
    return ($Raw -replace '\s+', ' ').Trim()
}

# --- Function to extract RAM slot details (capacity, speed, manufacturer, part number)

function Get-RAMSlotsFromObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][object]$Source,
        [hashtable]$ManufacturerMap
    )
    $props = $Source.PSObject.Properties.Name
    $count = $Source.RAMModuleCount
    if (-not $count) {
        $indices = foreach ($p in $props) { if ($p -match '^RAM(\d+)_CapacityGB$') { [int]$Matches[1] } }
        if ($indices) { $count = ($indices | Measure-Object -Maximum).Maximum } else { $count = 0 }
    }

    $slots = @()
    for ($i=1; $i -le $count; $i++) {
        $cap = $Source.("RAM${i}_CapacityGB")
        $spd = $Source.("RAM${i}_SpeedMHz")
        $man = $Source.("RAM${i}_Manufacturer")
        $pn  = $Source.("RAM${i}_PartNumber")

        if ($null -ne $cap -or $null -ne $spd -or $man -or $pn) {
            $slots += [pscustomobject]@{
                CapGB        = if ($cap -ne $null) { [int]$cap } else { $null }
                Speed        = if ($spd -ne $null) { [int]$spd } else { $null }
                Manufacturer = Get-FriendlyManufacturer -Raw $man -AdditionalMap $ManufacturerMap
                PartNumber   = ($pn -replace '\s+', ' ').Trim()
            }
        }
    }
    return $slots
}


# --- Function to summarize the installed RAM modules by size and speed ---

function Get-RAMSummary {
    [CmdletBinding()]
    param(
        [object]$Source,
        [hashtable]$ManufacturerMap
    )

    $mods = @()
    if ($Source) {
        $mods = Get-RAMSlotsFromObject -Source $Source -ManufacturerMap $ManufacturerMap
    }
    if (-not $mods -or $mods.Count -eq 0) {
        try { $ram = @(Get-CimInstance -ClassName Win32_PhysicalMemory) }
        catch { $ram = @(Get-WmiObject -Class Win32_PhysicalMemory) }
        foreach ($m in $ram) {
            $mods += [pscustomobject]@{
                CapGB        = [int][math]::Round($m.Capacity / 1GB, 0)
                Speed        = (@($m.Speed, $m.ConfiguredClockSpeed) | Where-Object { $_ -as [int] } | Select-Object -First 1)
                Manufacturer = Get-FriendlyManufacturer -Raw $m.Manufacturer -AdditionalMap $ManufacturerMap
                PartNumber   = ($m.PartNumber -replace '\s+', ' ').Trim()
            }
        }
    }
    if (-not $mods -or $mods.Count -eq 0) { return '' }

    $parts = foreach ($g in ($mods | Group-Object CapGB | Sort-Object Name)) {
        $count  = [int]$g.Count
        $cap    = [int]$g.Name
        $speeds = @($g.Group.Speed | Where-Object { $_ } | Sort-Object -Unique)

        $speedStr = if ($speeds.Count -eq 0) { '' }
                    elseif ($speeds.Count -eq 1) { "@$($speeds[0])" }
                    else { "@$($speeds -join '/')" }

        $pairs = $g.Group | ForEach-Object { "{0}/{1}" -f $_.Manufacturer, $_.PartNumber }
        $pairs = $pairs | ForEach-Object { $_ -replace '\s+', ' ' } 
        $uniquePairs = $pairs | Sort-Object -Unique

        if ($uniquePairs.Count -eq 1) {
            "{0}x{1}GB{2} [{3}]" -f $count, $cap, $speedStr, $uniquePairs[0]
        } else {
            $pairList = ($pairs | ForEach-Object { "($_)" }) -join ''
            "{0}x{1}GB{2} {3}" -f $count, $cap, $speedStr, $pairList
        }

    }

    $parts -join ' + '
}


# --- Report Builder ---

# Function to create PSCustomObject containing all system details

function Get-SystemReport {
    $cpu        = Get-ProcessorDetails
    $ramSummary = Get-RAMSummary

    [PSCustomObject]@{
        Username                 = Get-Username
        SystemModel              = Get-SystemModel
        SystemSerialNumber       = Get-SystemSerialNumber
        ComputerType             = Get-ComputerType
        MonitorCount             = Get-MonitorCount
        MonitorSetupDescription  = Get-MonitorSetupDescription
        ProcessorName            = ConvertTo-CPUModel $cpu.Name
        ProcessorCores           = $cpu.Cores
        ProcessorThreads         = $cpu.Threads
        InstalledRAMGB           = Get-InstalledRAMGB
        RAMModuleCount           = Get-RAMModuleCount
        RAMSummary               = $ramSummary
    }
}

# --- Main ---

$Report = Get-SystemReport

Write-Output ("Mon:{0}, Model:{1}, Ser:{2}, CPU:{3}, C:{4}, T:{5}, RAM:{6}GB ({7}), User:{8}" -f `
    $Report.MonitorSetupDescription, `
    $Report.SystemModel, `
    $Report.SystemSerialNumber, `
    $Report.ProcessorName, `
    $Report.ProcessorCores, `
    $Report.ProcessorThreads, `
    $Report.InstalledRAMGB, `
    $Report.RAMSummary, `
    $Report.Username)


# --- Optional: Export to CSV ---
# $csvPath = C:\Temp\JG-SystemReport.csv'
# $Report | Export-Csv -Path $csvPath -NoTypeInformation
# Write-Output "Report exported to: $csvPath"
