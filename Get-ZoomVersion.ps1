# get_zoom_version
# author: james romeo gaspar
# version: 1.0 06March2024
# version: 2.0 14July2024 - added path
# targeted for Windows Machines

$BasePath = "C:\Users"
$UniqueVersions = @()

foreach ($UserProfile in (Get-ChildItem -Path $BasePath -Directory -ErrorAction SilentlyContinue)) {
    $ZoomExePaths = @()
    
    # Check AppData\Roaming\Zoom\bin
    $ZoomExePaths += Get-ChildItem -Path (Join-Path -Path $UserProfile.FullName -ChildPath "AppData\Roaming\Zoom\bin\") -Filter "Zoom.exe" -File -Recurse -ErrorAction SilentlyContinue
    
    # Check Program Files\Zoom\bin
    $ZoomExePaths += Get-ChildItem -Path "C:\Program Files\Zoom\bin" -Filter "Zoom.exe" -File -Recurse -ErrorAction SilentlyContinue
    
    foreach ($ZoomExePath in $ZoomExePaths) {
        $ZoomVersion = (Get-Item $ZoomExePath.FullName).VersionInfo.FileVersion -replace ',', '.'
        if ($ZoomVersion -notin $UniqueVersions) {
            $UniqueVersions += $ZoomVersion
        }
    }
}

if ($UniqueVersions) {
    $Output = foreach ($Version in $UniqueVersions) {
        if ($Version -match '(\d+\.\d+\.\d+)\.(\d+)') {
            "$($Matches[1]) ($($Matches[2]))"
        } else {
            $Version
        }
    }
    Write-Output ($Output -join " | ")
} else {
    Write-Output "Zoom.exe not found on specified paths"
}
