#Author: James Romeo Gaspar 12.23.2022
#Revision: 1.1
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
$LastLoggedUN = (Get-ItemProperty -Path $RegPath).LastLoggedOnUser
if ($LastLoggedUN -ne $null) {$LastLoggedUser = $LastLoggedUN.Split("\")[1]}
$LastLoggedTS = (Get-CimInstance -Class Win32_UserProfile | Where-Object { ($_.LocalPath -ne $null) -and ($_.LocalPath.split('\')[-1] -eq $LastLoggedUser) }).LastUseTime
$LastLoggedTime = "$LastLoggedTS"
Write-Output "$LastLoggedUser ($LastLoggedTime)"
