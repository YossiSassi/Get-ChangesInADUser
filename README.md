# Get-ChangesInADUser
Checks for changes in AD users. Useful in finding who|when changed what property of an AD user. 

Requires 'Event Log Readers' or equivalent, to query Security event logs on Domain Controllers. No additional modules required. 

#### Make sure you enabled in advance the 'Audit Account Management' GPO setting for domain controllers ("User Account Management" under 'Advanced Audit Policy Configuration' in Group Policy)

NOTE: While can also check using ReplPropertyMetadata (quicker & no logs/auditing needed), the event collected here can also show WHO did the Change (the SubjectUsername).

NOTE2: For a focused operation on 'LogonWorkstations' (listing changes in userWorkstations attribute, based on ReplPropertyMetadata, without ANY auditing enabled AND in any time in the past), see separate script [Get-LogonworkstationsAttributeStatus.ps1](https://www.github.com/YossiSassi/Get-LogonworkstationsAttributeStatus)
