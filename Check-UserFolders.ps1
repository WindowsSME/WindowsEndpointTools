# Scans and summarizes user profile folders (like Documents, Downloads, etc.) for size and contents.

# Get all user profile directories from C:\Users
$UserProfiles = Get-ChildItem -Path "C:\Users" -Directory

# Get all profile registry keys
$ProfileRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
$ProfileSIDs = Get-ChildItem -Path $ProfileRegPath

# Create an array to store results
$Results = @()

foreach ($UserFolder in $UserProfiles) {
    $UserName = $UserFolder.Name
    $UserPath = $UserFolder.FullName

    # Try to find a matching SID in the registry
    $ProfileEntry = $ProfileSIDs | Where-Object {
        (Get-ItemProperty -Path $_.PSPath).ProfileImagePath -eq $UserPath
    }

    # If a match is found, get the SID; otherwise, mark as "Not Found"
    $SID = if ($ProfileEntry) { $ProfileEntry.PSChildName } else { "SID Not Found" }

    # Calculate folder size in GB
    try {
        $SizeBytes = (Get-ChildItem -Path $UserPath -Recurse -Force -ErrorAction Stop | Measure-Object -Property Length -Sum).Sum
        $FolderSize = if ($SizeBytes -gt 0) { "{0:N2}" -f ($SizeBytes / 1GB) } else { "0" }
    }
    catch {
        $FolderSize = "Access Denied"
    }

    # Store the result
    $Results += [PSCustomObject]@{
        User        = $UserName
        SID         = $SID
        FolderSizeGB = $FolderSize
    }
}

# Display results on screen in table format
$Results | Format-Table -AutoSize

# Define the output file path
$CsvFilePath = "C:\Temp\ProfileReport.csv"

# Export results to CSV
$Results | Export-Csv -Path $CsvFilePath -NoTypeInformation -Encoding UTF8

# Confirm output
Write-Output "`nReport saved to: $CsvFilePath"
