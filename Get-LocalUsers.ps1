
function Get-LocalUsers {

    # .SYNOPSIS
    # Retrieves a list of local user accounts on Windows devices.

    # .DESCRIPTION
    # This function attempts to retrieve local user accounts using multiple methods.
    # It first tries Get-LocalUser (available in modern PowerShell versions).
    # If that fails, it falls back to Get-CimInstance.
    # If Get-CimInstance also fails, it resorts to Get-WmiObject.
    # The output lists local user accounts with their enabled (E) or disabled (D) status.

    # .NOTES
    # Author: James Romeo Gaspar
    # Date: April 2, 2025

    [CmdletBinding()]
    param()

    $userList = @()

    # Primary method: Get-LocalUser (available in modern PowerShell versions)
    if (Get-Command -Name Get-LocalUser -ErrorAction SilentlyContinue) {
        try {
            # Retrieve local user accounts
            $localUsers = Get-LocalUser -ErrorAction Stop
            foreach ($user in $localUsers) {
                # Determine if the user account is enabled or disabled
                $status = if ($user.Enabled) { "(E)" } else { "(D)" }
                $userList += "$($user.Name)$status"
            }
        }
        catch {
            Write-Warning "Get-LocalUser failed. Trying fallback methods..."
        }
    }

    # Fallback 1: Get-CimInstance (Works on older PowerShell versions)
    if ($userList.Count -eq 0) {
        try {
            # Retrieve local user accounts using CIM
            $localUsers = Get-CimInstance -ClassName Win32_UserAccount -ErrorAction Stop |
                          Where-Object { $_.LocalAccount -eq $true }
            foreach ($user in $localUsers) {
                # Win32_UserAccount uses "Disabled" property; if not disabled, it is enabled
                $status = if (-not $user.Disabled) { "(E)" } else { "(D)" }
                $userList += "$($user.Name)$status"
            }
        }
        catch {
            Write-Warning "Get-CimInstance failed. Trying next fallback..."
        }
    }

    # Fallback 2: Get-WmiObject (Legacy method for older systems)
    if ($userList.Count -eq 0) {
        try {
            # Retrieve local user accounts using WMI
            $localUsers = Get-WmiObject -Class Win32_UserAccount -ErrorAction Stop |
                          Where-Object { $_.LocalAccount -eq $true }
            foreach ($user in $localUsers) {
                # Determine if the user account is enabled or disabled
                $status = if (-not $user.Disabled) { "(E)" } else { "(D)" }
                $userList += "$($user.Name)$status"
            }
        }
        catch {
            Write-Error "Unable to retrieve local users using any method."
            return
        }
    }

    # Output all user accounts as a single line, separated by commas
    Write-Output ($userList -join ", ")
}

# Run the function
Get-LocalUsers
