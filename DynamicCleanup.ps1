<#
.SYNOPSIS
    Clear temporary folders until their combined size is below
    a configurable threshold (default 9 GB), tightening the retention
    window from 60 → 45 → 30 → 15 days as required.
#>


[CmdletBinding()]
param(
    [string[]] $Path = @(
        "C:\Windows\Temp"
        "C:\ProgramData\Logs"
    ),

    [int]      $SizeThresholdGB = 20,
    [switch]   $Simulation
)

[int[]]$RetentionDays = 60,45,30

$totalBytesFreed = 0
$success         = $true

try {
    foreach ($days in $RetentionDays) {

        $cutOff = (Get-Date).AddDays(-$days)
        Write-Verbose "Applying retention of $days days (cut-off: $cutOff)…"

        foreach ($p in $Path) {
            if (-not (Test-Path -LiteralPath $p)) {
                Write-Warning "Skipping '$p' (does not exist)"
                continue
            }

            $oldFiles = Get-ChildItem -LiteralPath $p -File -Recurse -ErrorAction SilentlyContinue |
                        Where-Object { $_.LastWriteTime -lt $cutOff }

            $freedBytes = ($oldFiles | Measure-Object Length -Sum).Sum
            if (-not $freedBytes) { $freedBytes = 0 }
            $totalBytesFreed += $freedBytes

            if (-not $Simulation) {
                $oldFiles | Remove-Item -Force -ErrorAction SilentlyContinue
            }
        }

        $currentSize = 0
        foreach ($p in $Path) {
            if (Test-Path -LiteralPath $p) {
                $currentSize += (Get-ChildItem -LiteralPath $p -File -Recurse -ErrorAction SilentlyContinue |
                                 Measure-Object Length -Sum).Sum
            }
        }

        Write-Verbose ("After {0}-day retention size is {1:N1} GB" -f $days, ($currentSize / 1GB))

        if ($currentSize -le ($SizeThresholdGB * 1GB)) {
            Write-Verbose "Size is now below threshold – stopping early."
            break
        }
    }
}
catch {
    Write-Warning $_
    $success = $false
}

if ($Simulation) {
    "{0:N1} GB would be freed (simulation only)" -f ($totalBytesFreed / 1GB)
}
elseif ($success) {
    "Maintenance completed ({0:N1} GB)" -f ($totalBytesFreed / 1GB)
}
else {
    "Failed – an error occurred during maintenance."
}
