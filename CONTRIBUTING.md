# LAZY ADMIN SCRIPTS | CONTRIBUTING

Thank you for taking the time to contribute! 👍

While you are free to use the script however you want, I have noticed that collaborative work tipically yields better results. Hence, contributions are welcomed and I will try to reply to every request.

## IMPORTANT
- Policies are always enforced system-wide, except in cases where that is not possible or where there may be the need of allowing the user to change them (e. g. for troubleshooting).
- Security-related settings that are already optimal by default are not currently enforced in this script. This is not necessarily the best practice, but it was done to reduce the . If by any chance  contributions appear, this might change in the future.
- While the code is yet to be documented, I have strived to include only current settings that have been officially documented. Do not be surprised if you do not find here some older or undocumented settings that are available in other tools.

## ROADMAP
- [ ] Add the ability to create backups (i. e. registry) and to restore them.
- [ ] Add the ability to fetch the latest versions of WindowsSpyBlocker and hosts (oisd) files and include them in the script.
- [ ] Add more common CFA exclusions (mainly dependant on feedback) and the ability to search for custom executable locations to CFA
- [ ] Add WDAC block rules (for future reference https://mattifestation.medium.com/windows-defender-application-control-wdac-updates-in-20h2-and-building-a-simple-secure-4fd4ee86de4).
- [ ] Comment the changes being made and their source documentation.
- [ ] Convert the script to PowerShell (cleaner code?).
- [ ] Convert Group Policy reg keys into real GPOs (using PolicyPlus?) and add them to the script.
- [ ] Convert 'service' commands to reg keys - this would allow to disable services that refuse to be disabled with 'service' (at least while using cmd).
