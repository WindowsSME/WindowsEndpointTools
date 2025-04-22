#Author: James Romeo Gaspar
#Revision: 1.2 [13Jan2023]
$Win_profpath = "C:\Users\"
$SkippedAccounts = @('ADMIN' , 'Public' , 'NetworkService' , 'LocalService' , 'systemprofile')
$UserProfileFolders = (Get-ChildItem -Path $Win_profpath | Where-Object {($_.Name -ne $null) -and ($_.Name -notin $SkippedAccounts)}).FullName
$UserProfileSIDs = (Get-CimInstance -Class Win32_UserProfile | Where-Object { ($_.LocalPath -ne $null) -and ($_.LocalPath.split('\')[-1] -notin $SkippedAccounts) }).LocalPath
$DefProps = @(
    'DriveLetter'
    'FileSystemLabel'
    'FileSystem'
    'DriveType'
    'HealthStatus'
    'OperationalStatus'
    @{
        Name = 'SizeRemaining'
        Expression = { "{0:N3} Gb" -f ($_.SizeRemaining/ 1Gb) }
    }
    @{
        Name = 'Size'
        Expression = { "{0:N3} Gb" -f ($_.Size / 1Gb) }
    }
    @{
        Name = '% Free'
        Expression = { "{0:P}" -f ($_.SizeRemaining / $_.Size) }
    }
)
$DiskSpace = (Get-Volume -DriveLetter C | Select-Object $DefProps).Size
$FreeSpace = (Get-Volume -DriveLetter C | Select-Object $DefProps).SizeRemaining
$PercentageFree = (Get-Volume -DriveLetter C | Select-Object $defprops)."% Free"
if ($($UserProfileFolders.Count) -eq $($UserProfileSIDs.Count)) {$ProfileMatchStatus = "Matched"}
else {$ProfileMatchStatus = "Mismatched"}
Write-Output "User Profiles : $($UserProfileFolders.Count)($($UserProfileSIDs.Count)) | $ProfileMatchStatus | $FreeSpace ($PercentageFree) Free of $DiskSpace"
