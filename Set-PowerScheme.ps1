function Set-PowerScheme {

    # SetPowerScheme.ps1
    # Script to create a separate high performance power scheme based on current active
    # Author: James Romeo Gaspar
    # Date: 25.Oct.2024
    # Revision 1.1 : 19December2024 : Removed editing processor, display settings. Added Hibernate and Sleep set to Never.
    # Revision 2.0 : 03February2025 : Added fix to remove multiple duplicate High Performance power schemes and skip creating if High Performance scheme is already set and present.

    Write-Output "Checking for existing 'High Performance' power schemes..."
    $existingSchemes = powercfg /list
    $highPerfGUIDs = @()
    $balancedGUID = ""
    $activeGUID = ""

    foreach ($line in $existingSchemes) {
      
        if ($line -match 'Power Scheme GUID:\s*([a-f0-9-]+)\s*\((.*?)\)') {
            $guid = $matches[1]
            $name = $matches[2]
            Write-Output "Found scheme: $name with GUID: $guid"
            if ($name -eq "Balanced") {
                $balancedGUID = $guid
            } elseif ($name -eq "High Performance") {
                $highPerfGUIDs += $guid
            }
        }
    }

    Write-Output "High Performance GUIDs found: $($highPerfGUIDs -join ', ')"

    $activeSchemeOutput = powercfg /getactivescheme
    if ($activeSchemeOutput -match 'Power Scheme GUID:\s*([a-f0-9-]+)') {
        $activeGUID = $matches[1]
        Write-Output "Active power scheme found: $activeGUID"
    } else {
        Write-Output "Could not extract active GUID."
        return
    }

    if ($highPerfGUIDs.Count -gt 1) {
        Write-Output "Multiple 'High Performance' schemes found. Retaining the most recent and deleting others..."
        $highPerfGUIDs = $highPerfGUIDs | Sort-Object -Descending
        $latestHighPerfGUID = $highPerfGUIDs[0]
        $highPerfGUIDs[1..($highPerfGUIDs.Count - 1)] | ForEach-Object {
            if ($_ -ne $activeGUID) {
                Write-Output "Deleting duplicate High Performance scheme: $_"
                powercfg /delete $_
            } else {
                Write-Output "Cannot delete active power scheme: $_"
            }
        }
    } elseif ($highPerfGUIDs.Count -eq 1) {
        $latestHighPerfGUID = $highPerfGUIDs[0]
    }

    if ($latestHighPerfGUID) {
        Write-Output "Activating retained 'High Performance' scheme: $latestHighPerfGUID"
        powercfg /s $latestHighPerfGUID
        return
    }

    Write-Output "No 'High Performance' scheme found. Creating one..."
    Write-Output "Duplicating active power scheme..."
    $dupOutput = powercfg /duplicatescheme $activeGUID

    if ($dupOutput -match 'Power Scheme GUID:\s*([a-f0-9-]+)') {
        $newGUID = $matches[1]
        Write-Output "New power scheme duplicated: $newGUID"
    } else {
        Write-Output "Could not extract new GUID."
        return
    }

    Write-Output "Setting Turn off hard disk after to 0..."
    powercfg /setacvalueindex $newGUID 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0
    powercfg /setdcvalueindex $newGUID 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0
    Write-Output "Done."

    Write-Output "Setting Display Power to 0..."
    powercfg /setacvalueindex $newGUID 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 0
    powercfg /setdcvalueindex $newGUID 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 0
    Write-Output "Done."

    Write-Output "Setting Hibernate to Never..."
    powercfg /setacvalueindex $newGUID 238c9fa8-0aad-41ed-83f4-97be242c8f20 9d7815a6-7ee4-497e-8888-515a05f02364 0
    powercfg /setdcvalueindex $newGUID 238c9fa8-0aad-41ed-83f4-97be242c8f20 9d7815a6-7ee4-497e-8888-515a05f02364 0
    Write-Output "Done."

    Write-Output "Setting Sleep to Never..."
    powercfg /setacvalueindex $newGUID 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0
    powercfg /setdcvalueindex $newGUID 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0
    Write-Output "Done."

    Write-Output "Changing Power Plan Name to 'High Performance'..."
    powercfg /changename $newGUID "High Performance"
    powercfg /s $newGUID
    Write-Output "Done."

    $activeSchemeName = powercfg /getactivescheme
    Write-Output "Completed all tasks. Active $activeSchemeName"

    Write-Output "Listing all existing power schemes:"
    powercfg /list
}
Set-PowerScheme
