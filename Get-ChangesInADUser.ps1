# Checks for changes in AD users (focused on Logonworkstations for monitoring potential changes in Policy settings)
# by 1nTh35h311 (comments welcome to yossis@protonmail.com)
# Requires 'Event Log Readers' membership or equivalent, to query Security event logs on Domain Controllers. No additional modules required.
# NOTE: Make sure you enabled in advance the 'Audit Account Management' GPO setting for domain controllers ("User Account Management" under 'Advanced Audit Policy Configuration' in Group Policy)
# NOTE2: While can also check using ReplPropertyMetadata (quicker & no logs/auditing needed), the Event collected here can also show WHO did the Change (the SubjectUsername).
# NOTE3: For a focused operation on 'LogonWorkstations' (listing changes in userWorkstations attribute, based on ReplPropertyMetadata, without ANY auditing enabled AND in any time in the past), see separate script Get-LogonworkstationsAttributeStatus (https://www.github.com/YossiSassi/Get-LogonworkstationsAttributeStatus.ps1)

param (
    [cmdletbinding()]
    [switch]$DoNotOpenResultsInGrid
)

# Get events data from the Domain Controllers on the network via WinRM (port 5985)
$DCs = ([adsisearcher]"(&(objectCategory=computer)(|(primarygroupid=521)(primarygroupid=516)))").FindAll().Properties.name;

$Event4738 = @();
$i = 1;

$DCs | foreach {
    $DC = $_;
    # check if ANY 4738 events exist/are collected
    if (Get-WinEvent -ComputerName $DC -FilterHashtable @{logname='security';id=4738} -MaxEvents 1) 
        {
            Write-Host "[x] Fetching relevant events from $DC ($i of $(($DCs | Measure-Object).count))..." -ForegroundColor Cyan;
            $Event4738 += Get-WinEvent -ComputerName $DC -FilterHashtable @{logname='security';id=4738}
        }
    else
        {
            Write-Host "[!] No relevant events found on $DC (ensure events are collected/configured by GPO)" -ForegroundColor Yellow;
        }
    $i++
}

$TotalEvents = ($Event4738 | Measure-Object).Count;

if ($TotalEvents -le 0)
    {
        Write-Host "[x] No relevant events found" -ForegroundColor Yellow;
        break
    }

Write-Host "[x] Found $('{0:N0}' -f $TotalEvents) events." -ForegroundColor Cyan;

[string]$LogFile = "$(Get-Location)\ObjectChanges_$ReportType_$(Get-Date -Format HHmmssddmmyyyy).csv";
$DataForCSV = @();
$DataForCSV += "TimeChanged|TargetUserName|SubjectUserName|AttributeChanged|NewAttributeValue";

$Event4738 | foreach {
    $EventDate = $_.TimeCreated;
    $EventXML = ([xml]$_.ToXml()).event.Eventdata.Data

    $EventXML[8..$($EventXML.Count-1)] | foreach {if ($_.'#text' -ne "-") {
        $attribChanged = $($_.name);
        $AttribValue = $($_.'#text')}
    }

    # If logonworkstations was changed, and value is %%1793, it means Empty (the default setting)
    if ($attribChanged -eq "UserWorkstations" -and $AttribValue -eq "%%1793") {$AttribValue = "EMPTY (Reset back to default)"}
    
    # Add entry to CSV log data
    $DataForCSV += "$EventDate|$($EventXML[1].'#text')|$($EventXML[5].'#text')|$attribChanged|$AttribValue";

    Write-Verbose "Change time: $EventDate";
    Write-Verbose "TargetUserName: $($EventXML[1].'#text')";
    Write-Verbose "SubjectUserName: $($EventXML[5].'#text')";    
    Write-Verbose "Attribute changed: $attribChanged"; 
    Write-Verbose "New attribute value: $AttribValue";
}

if (!$DoNotOpenResultsInGrid)
    {
        $DataForCSV | ConvertFrom-Csv -Delimiter "|" | sort TargetUsername, TimeChanged -Descending | Out-GridView -Title "Object Changes (Total: $TotalEvents)"        
    }

# write to Log file
$DataForCSV | Out-File $Logfile -Append;

Write-Host "[x] Log file written to $Logfile." -ForegroundColor Green