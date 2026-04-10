# Windows Endpoint Tools

PowerShell scripts for running diagnostics and performing lightweight remediation on Windows endpoints. Ideal for helpdesk use, pre-deployment health checks, or remote support workflows.

---

## Included Scripts

### User & Account Info

- [Get-LastLoggedUser.ps1](./Get-LastLoggedUser.ps1)  
  Returns the most recent interactive user login - useful for tracking device ownership or troubleshooting.

- [Get-LocalUsers.ps1](./Get-LocalUsers.ps1)  
  Lists all local user accounts on the system along with status indicators.

### Hardware & Device Info

- [Get-Monitor-Serial.ps1](./Get-Monitor-Serial.ps1)  
  Fetches serial numbers of connected monitors - helpful for physical asset management and inventory.

- [Get-WebcamInfo.ps1](./Get-WebcamInfo.ps1)  
  Detects available webcam devices, identifies if they are internal or external, and includes fallback detection via WMI.

- [Get-AppID.ps1](./Get-AppID.ps1)  
  Retrieves the AppID (Application User Model ID) for Windows apps - useful for notifications or taskbar tweaks.

### System Health & Logs

- [Get-SystemInformation.ps1](./Get-SystemInformation.ps1)  
  Collects comprehensive system details including OS version, hardware specs, and network configuration in one view.

- [QAChecker.ps1](./QAChecker.ps1)  
  Performs a series of basic system checks (uptime, disk space, antivirus status, etc.) to verify that the system meets internal QA standards.

- [Get-LogZips.ps1](./Get-LogZips.ps1)  
  Collects logs from common system locations (Event Logs, WindowsUpdate, etc.), then compresses them for export or escalation.

- [DynamicCleanup.ps1](./DynamicCleanup.ps1)  
  Automates the removal of temporary files and system bloat to recover disk space dynamically.

### Storage Analysis

- [Profile-SpaceCheck.ps1](./Profile-SpaceCheck.ps1)  
  Scans all user profile folders and reports disk usage, helping identify storage bloat and cleanup candidates.

- [Check-DiskUsage.ps1](./Check-DiskUsage.ps1)  
  Checks free space across system drives and reports disk usage.

- [Check-UserFolders.ps1](./Check-UserFolders.ps1)  
  Scans and summarizes user profile folders (like Documents, Downloads, etc.) for size and contents.

- [Compare-ChromeToProfileSize.ps1](./Compare-ChromeToProfileSize.ps1)  
  Analyzes how much of a user's profile is occupied specifically by Google Chrome data/cache.

### MDM & VPN Management

- [Remove-AirwatchAgent.ps1](./Remove-AirwatchAgent.ps1)  
  Forcefully removes the Workspace ONE (Airwatch) agent and cleans up associated services.

- [Reinstall-WS1Hub.ps1](./Reinstall-WS1Hub.ps1)  
  Automates the repair and reinstallation of the Workspace ONE Intelligent Hub.

- [Get-WS1UninstallInfo.ps1](./Get-WS1UninstallInfo.ps1)  
  Retrieves specific registry uninstall strings and GUIDs for Workspace ONE components.

- [Get-Airwatch-MSIs.ps1](./Get-Airwatch-MSIs.ps1)  
  Identifies all installed MSI packages related to the Airwatch/Workspace ONE environment.

- [GlobalProtect-Rollback.ps1](./GlobalProtect-Rollback.ps1)  
  A general-purpose script to automate the downgrade or rollback of the Palo Alto GlobalProtect VPN client.

- [Rollback-GP-628-to-625.ps1](./Rollback-GP-628-to-625.ps1)  
  Targeted rollback script specifically for reverting GlobalProtect version 6.2.8 to 6.2.5.

### Software Inventory & Audit

- [Get-ZoomVersion.ps1](./Get-ZoomVersion.ps1)  
  Scans user profiles and system paths to list unique installed Zoom versions on a Windows device.

- [Get-ChromeHistoryFile.ps1](./Get-ChromeHistoryFile.ps1)  
  Locates the Chrome History database file for a user profile - useful for diagnostic or forensic log collection.

### Security & Compliance

- [Get-BitLockerComplianceReport.ps1](./Get-BitLockerComplianceReport.ps1)  
  Generates a compliance report detailing BitLocker encryption status across system volumes, useful for audits and security checks.

- [Get-BitlockerStatus.ps1](./Get-BitlockerStatus.ps1)  
  Retrieves the current BitLocker encryption status of all system drives, providing a quick local security overview.

- [XDR-AppChecker.ps1](./XDR-AppChecker.ps1)  
  Checks for the presence, status, or installation of an XDR endpoint protection agent.

- [XDR-ServerStatusCheck.ps1](./XDR-ServerStatusCheck.ps1)  
  Tests connectivity and response from the XDR management server to verify communication from the endpoint.

### Deployment & Configuration

- [Invoke-StandardMsiInstall.ps1](./Invoke-StandardMsiInstall.ps1)  
  A standardized wrapper for MSI installations that enforces logging and quiet switches.

- [Set-PowerScheme.ps1](./Set-PowerScheme.ps1)  
  Configures a High Performance power plan, removes duplicates, and sets display, sleep, and hibernate timeouts to "Never."

- [Hide-SSID.ps1](./Hide-SSID.ps1)  
  Configures the endpoint to ignore or hide specific SSIDs from the available networks list.

- [Compare-RegFiles.ps1](./Compare-RegFiles.ps1)  
  Compares three `.reg` files to identify added, removed, or changed settings and generates diff files and a CSV summary.

---

## Usage

Each script can be run in a PowerShell window. Some may require admin rights.

```powershell
.\ScriptName.ps1
```

---

## Notes
Great for use in onboarding scripts or support toolkits.
Tested on Windows 10/11 systems.

---

## Contributions
If you have more useful system checks, feel free to fork and add to this toolkit.

---
## License
MIT License
