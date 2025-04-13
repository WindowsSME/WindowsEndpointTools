# QASystemChecks

A collection of PowerShell scripts designed for quick system audits, diagnostics, and quality assurance checks in Windows environments. These tools are great for helpdesk, IT audits, or onboarding checklists.

---

## Included Scripts

### [QAChecker.ps1](./QAChecker.ps1)
Performs a series of checks to ensure the system meets internal QA standards before deployment.

### [Profile-SpaceCheck.ps1](./Profile-SpaceCheck.ps1)
Scans all user profiles and reports on disk space usage to help identify bloat or cleanup candidates.

### [Get-LastLoggedUser.ps1](./Get-LastLoggedUser.ps1)
Returns the last logged-in user on a device, helpful for tracking user activity or ownership.

### [Get-LogZips.ps1](./Get-LogZips.ps1)
Collects key logs and zips them for export, ideal for remote troubleshooting or escalations.

### [Get-Monitor-Serial.ps1](./Get-Monitor-Serial.ps1) *(optional)*
Retrieves serial numbers of attached monitors for inventory or diagnostics.

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
