<#
    Script: Compare-RegFiles.ps1
    Purpose: Compare three Windows Registry (.reg) files
             to identify added, removed, or changed settings.
    Output:
        - Sorted versions of the input files
        - Pairwise diff files
        - List of unique lines not shared by all
        - CSV report showing key differences with change type
    Note: "N/A" indicates a setting is missing from a file

    Author: James Romeo Gaspar
    Date: May 2, 2025
#>

# --------------------------------------------
# Step 1: Define input file paths
# --------------------------------------------
$file1 = "Inline upgrade working to Working.reg"
$file2 = "Not Working.reg"
$file3 = "Working Fresh Installation.reg"

# Define output paths for sorted versions
$sorted1 = "Inline upgrade working to Working._sorted.reg"
$sorted2 = "Not Working_sorted.reg"
$sorted3 = "Working Fresh Installation_sorted.reg"

# --------------------------------------------
# Step 2: Sort input files for consistent diffing
# --------------------------------------------
Get-Content $file1 | Sort-Object | Set-Content $sorted1
Get-Content $file2 | Sort-Object | Set-Content $sorted2
Get-Content $file3 | Sort-Object | Set-Content $sorted3

# --------------------------------------------
# Step 3: Perform pairwise comparisons
# --------------------------------------------
Compare-Object (Get-Content $sorted1) (Get-Content $sorted2) -PassThru |
    Out-File "File1_vs_File2.diff.txt"

Compare-Object (Get-Content $sorted1) (Get-Content $sorted3) -PassThru |
    Out-File "File1_vs_File3.diff.txt"

Compare-Object (Get-Content $sorted2) (Get-Content $sorted3) -PassThru |
    Out-File "File2_vs_File3.diff.txt"

# --------------------------------------------
# Step 4: Identify lines not common to all three files
# --------------------------------------------
$allLines = Get-Content $sorted1, $sorted2, $sorted3
$grouped = $allLines | Group-Object | Where-Object { $_.Count -lt 3 }
$grouped | ForEach-Object { $_.Group } | Set-Content "Unique_Across_Files.reg"

# --------------------------------------------
# Step 5: Parse registry lines into dictionaries
# --------------------------------------------
function Parse-RegLines($lines) {
    $dict = @{}
    foreach ($line in $lines) {
        if ($line -match '^\s*"(.+?)"\s*=\s*(.+)$') {
            $key = '"' + $matches[1] + '"'
            $value = $matches[2].Trim()
            $dict[$key] = $value
        }
    }
    return $dict
}

# Parse key-value pairs from each sorted file
$dict1 = Parse-RegLines (Get-Content $sorted1)
$dict2 = Parse-RegLines (Get-Content $sorted2)
$dict3 = Parse-RegLines (Get-Content $sorted3)

# Get all unique registry keys
$allKeys = $dict1.Keys + $dict2.Keys + $dict3.Keys | Sort-Object -Unique

# --------------------------------------------
# Step 6: Build comparison table with change type
# --------------------------------------------
$rows = foreach ($key in $allKeys) {
    $val1 = $dict1[$key]
    $val2 = $dict2[$key]
    $val3 = $dict3[$key]

    if ($val1) { $f1 = $val1 } else { $f1 = 'N/A' }
    if ($val2) { $f2 = $val2 } else { $f2 = 'N/A' }
    if ($val3) { $f3 = $val3 } else { $f3 = 'N/A' }

    $changeType = ""

    if ($f1 -eq $f2 -and $f2 -eq $f3) {
        $changeType = "Unchanged"
    } elseif ($f1 -eq 'N/A' -or $f2 -eq 'N/A' -or $f3 -eq 'N/A') {
        $changeType = "Added/Removed"
    } elseif ($f1 -ne $f2 -or $f2 -ne $f3 -or $f1 -ne $f3) {
        $changeType = "Changed"
    }

    [PSCustomObject]@{
        Setting    = $key
        File1      = $f1
        File2      = $f2
        File3      = $f3
        ChangeType = $changeType
    }
}

# --------------------------------------------
# Step 7: Export comparison to CSV
# --------------------------------------------
$rows | Export-Csv -Path "Registry_Comparison_Table.csv" -NoTypeInformation -Encoding UTF8

# --------------------------------------------
# Step 8: Final status message
# --------------------------------------------
Write-Host "Comparison complete. Files generated:"
Write-Host " - File1_vs_File2.diff.txt"
Write-Host " - File1_vs_File3.diff.txt"
Write-Host " - File2_vs_File3.diff.txt"
Write-Host " - Unique_Across_Files.reg"
Write-Host " - Registry_Comparison_Table.csv"
