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
- [ ] Add the ability to search for custom executable locations to CFA.
- [ ] Add more common CFA exclusions - this would mainly depend on feedback.
- [ ] Comment the changes being made and the source of their documentation.
- [ ] Convert the script to PowerShell (cleaner code?).
- [ ] Convert Group Policy reg keys into real GPOs (using PolicyPlus?) and add them to the script.
- [ ] Convert 'service' commands to reg keys - this would allow to disable services that refuse to be disabled with 'service' (while using cmd).