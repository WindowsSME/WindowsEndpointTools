# Checks free space across system drives and reports disk usage.
param (
    [string]$Drive = "C:\",  
    [int]$TopFolders = 30,   
    [int]$FileSizeThresholdMB = 500, 
    [string]$ExportCSV = ""  
)

# Function to calculate folder size
function Get-FolderSize {
    param ([string]$Path)
    try {
        $size = (Get-ChildItem -Path $Path -Recurse -Force -ErrorAction Stop | Measure-Object -Property Length -Sum).Sum
        return "{0:N2}" -f ($size/1GB)
    } catch {
        return "Access Denied"
    }
}

# Get drive space information
$DriveLetter = ($Drive -replace ":","")  # Remove colon from C:\
$driveInfo = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Name -eq $DriveLetter -or $_.Root -like "$Drive*" }

Write-Host "Drive Information:"
$driveInfo | Select-Object Name, 
    @{Name="TotalSizeGB";Expression={if ($_.Used -ne $null -and $_.Free -ne $null) {"{0:N2}" -f (($_.Used + $_.Free)/1GB)} else {"N/A"}}}, 
    @{Name="UsedSpaceGB";Expression={if ($_.Used -ne $null) {"{0:N2}" -f ($_.Used/1GB)} else {"N/A"}}}, 
    @{Name="FreeSpaceGB";Expression={if ($_.Free -ne $null) {"{0:N2}" -f ($_.Free/1GB)} else {"N/A"}}} | Format-Table -AutoSize

# Get largest folders in root of C:\
Write-Host "`nTop $TopFolders largest folders in $Drive"
$largestFolders = Get-ChildItem -Path $Drive -Directory -ErrorAction SilentlyContinue |
    ForEach-Object { 
        $size = Get-FolderSize -Path $_.FullName
        [PSCustomObject]@{
            Folder = $_.FullName
            SizeGB = $size
        }
    } | Sort-Object {[decimal]($_.SizeGB -replace "Access Denied","0")} -Descending | Select-Object -First $TopFolders

$largestFolders | Format-Table -AutoSize

# Scan C:\Users separately
Write-Host "`nScanning C:\Users separately..."
$usersSize = Get-FolderSize -Path "C:\Users"
Write-Host "C:\Users Total Size: $usersSize GB"

# Get profile count in C:\Users
$userProfiles = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue
$userProfileCount = $userProfiles.Count
Write-Host "Number of user profiles in C:\Users: $userProfileCount"

# Get profile count from registry
$registryProfiles = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" -ErrorAction SilentlyContinue
$registryProfileCount = $registryProfiles.Count
Write-Host "Number of user profiles in registry: $registryProfileCount"

# Get largest subfolders in C:\Users
Write-Host "`nTop $TopFolders largest subfolders in C:\Users"
$largestUserFolders = $userProfiles |
    ForEach-Object { 
        $size = Get-FolderSize -Path $_.FullName
        [PSCustomObject]@{
            Folder = $_.FullName
            SizeGB = $size
        }
    } | Sort-Object {[decimal]($_.SizeGB -replace "Access Denied","0")} -Descending | Select-Object -First $TopFolders

$largestUserFolders | Format-Table -AutoSize

# Find large files in entire C:\
Write-Host "`nFiles larger than $FileSizeThresholdMB MB:"
$largeFiles = Get-ChildItem -Path $Drive -Recurse -File -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Length -gt ($FileSizeThresholdMB * 1MB) } |
    Select-Object FullName, @{Name="SizeMB";Expression={"{0:N2}" -f ($_.Length/1MB)}} |
    Sort-Object SizeMB -Descending

$largeFiles | Format-Table -AutoSize

# Export to CSV if specified
if ($ExportCSV -ne "") {
    $largestFolders | Export-Csv -Path "$ExportCSV-LargestFolders.csv" -NoTypeInformation
    $largestUserFolders | Export-Csv -Path "$ExportCSV-LargestUserFolders.csv" -NoTypeInformation
    $largeFiles | Export-Csv -Path "$ExportCSV-LargeFiles.csv" -NoTypeInformation
    Write-Host "`nResults exported to $ExportCSV"
}
