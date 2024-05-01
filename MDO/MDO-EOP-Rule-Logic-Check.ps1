# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
This script retrieves various types of Security/Threat policies from an Exchange Online environment and checks for logical inconsistencies in their configuration.

.DESCRIPTION
The script first defines a hashtable of cmdlets that are used to retrieve different types of policies from Exchange Online, including Presets, anti-phishing/spam/malware, and built-in. Each cmdlet is associated with a specific policy type.

It then loops through each cmdlet, invoking it to retrieve the corresponding policies. For each policy, it checks the inclusion and exclusion properties for logical inconsistencies. These properties define which users, groups, or domains the policy applies to or excludes.

The checks performed are as follows:
 1. If individual users are included and excluded, it prints a message indicating that the policy could only apply to users listed in the inclusions.
 2. If email domains are included and excluded, it prints a message indicating that the policy could only apply to domains listed in the inclusions.
 3. If users are included along with groups, it prints a message indicating that the policy will only apply to users who are also members of any groups specified, making the group inclusion redundant and confusing.
 4. If users are included along with domains, it prints a message indicating that the policy will only apply to users whose email domains also match any domains specified, making the domain inclusion redundant and confusing.
 5. If no logical inconsistencies found, prints that out.
 6. This script is backed by documentation about script priorities and behavior at the time of writing.

.NOTES
The script checks for connection to AzureAD and Exchange Online, and, if not connected, connects you before running this script.
Only read-only permissions are needed as the script only reads from policies.
#>

param(
    [Parameter(ParameterSetName = 'Applied')]
    [switch]$SkipVersionCheck,

    [Parameter(Mandatory = $true, ParameterSetName = "ScriptUpdateOnly")]
    [switch]$ScriptUpdateOnly
)

. $PSScriptRoot\..\Shared\LoggerFunctions.ps1
. $PSScriptRoot\..\Shared\OutputOverrides\Write-Host.ps1

function Write-HostLog ($message) {
    if (![string]::IsNullOrEmpty($message)) {
        $Script:HostLogger = $Script:HostLogger | Write-LoggerInstance $message
    }
}

SetWriteHostAction ${Function:Write-HostLog}

$LogFileName = "MDO-EOP-Rule-Logic-Check"
$StartDate = Get-Date
$StartDateFormatted = ($StartDate).ToString("yyyyMMddhhmmss")
$Script:HostLogger = Get-NewLoggerInstance -LogName "$LogFileName-Results-$StartDateFormatted" -LogDirectory $PSScriptRoot -AppendDateTimeToFileName $false -ErrorAction SilentlyContinue

. $PSScriptRoot\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1

$BuildVersion = ""

Write-Host ("MDO-EOP-Rule-Logic-Check.ps1 script version $($BuildVersion)") -ForegroundColor Green

if ($ScriptUpdateOnly) {
    switch (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/MDO-EOP-Rule-Logic-Check-VersionsURL" -Confirm:$false) {
    ($true) { Write-Host ("Script was successfully updated") -ForegroundColor Green }
    ($false) { Write-Host ("No update of the script performed") -ForegroundColor Yellow }
        default { Write-Host ("Unable to perform ScriptUpdateOnly operation") -ForegroundColor Red }
    }
    return
}

if ((-not($SkipVersionCheck)) -and
    (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/MDO-EOP-Rule-Logic-Check-VersionsURL" -Confirm:$false)) {
    Write-Host ("Script was updated. Please re-run the command") -ForegroundColor Yellow
    return
}

. $PSScriptRoot\..\Shared\Connect-M365.ps1

Write-Output "`n"
Write-Host "Disclaimer:

The sample scripts are not supported under any Microsoft standard support program or service.
The sample scripts are provided AS IS without warranty of any kind.
Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever
(including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss)
arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages." -ForegroundColor Yellow

Write-Output "`n"
Write-Host "This script retrieves all Threat policies and checks for logical inconsistencies in their configuration." -ForegroundColor Yellow

#Connect to EXO PS
$SessionCheck = Get-PSSession | Where-Object { $_.Name -like "*ExchangeOnline*" -and $_.State -match "opened" }
if ($null -eq $SessionCheck) {
    Connect-EXO
}

# Define the cmdlets to retrieve policies from and their corresponding policy types
$Cmdlets = @{
    "Get-HostedContentFilterRule"  = "Anti-spam Policy"
    "Get-EOPProtectionPolicyRule"  = "Preset security policies Policy"
    "Get-MalwareFilterRule"        = "Malware Policy"
    "Get-ATPProtectionPolicyRule"  = "MDO (SafeLinks/SafeAttachments) Policy in preset security policies"
    "Get-AntiPhishRule"            = "Anti-phishing Policy"
    "Get-SafeLinksRule"            = "Safe Links Policy"
    "Get-SafeAttachmentRule"       = "Safe Attachment Policy"
    "Get-ATPBuiltInProtectionRule" = "Built-in protection preset security Policy"
}
$IssueCounter = 0

# Loop through each cmdlet
foreach ($Cmdlet in $Cmdlets.Keys) {
    # Retrieve the policies
    $Policies = & $Cmdlet

    # Loop through each policy
    foreach ($Policy in $Policies) {
        # Initialize an empty list to store issues
        $Issues = @()

        # Check the logic of the policy and add issues to the list
        if ($Policy.SentTo -and $Policy.ExceptIfSentTo) {
            $Issues += "User inclusions and exclusions. Excluding and including Users individually is redundant and confusing as only the included Users could possibly be included.`nSuggestion: excluding individual Users should be used to exclude from group or domain inclusions, if needed."
        }
        if ($Policy.RecipientDomainIs -and $Policy.ExceptIfRecipientDomainIs) {
            $Issues += "Domain inclusions and exclusions. Excluding and including Domains is redundant and confusing as only the included Domains could possibly be included."
        }
        if ($Policy.SentTo -and $Policy.SentToMemberOf) {
            $Issues += "Illogical inclusions of Users and Groups. The policy will only apply to Users who are also members of any Groups you have specified. This makes the Group inclusion redundant and confusing.`nSuggestion: use one or the other type of inclusion."
        }
        if ($Policy.SentTo -and $Policy.RecipientDomainIs) {
            $Issues += "Illogical inclusions of Users and Domains. The policy will only apply to Users whose email domains also match any Domains you have specified. This makes the Domain inclusion redundant and confusing.`nSuggestion: use one or the other type of inclusion."
        }

        # If there are any issues, print the policy details once and then list all the issues
        if ($Issues.Count -gt 0) {
            Write-Host ("`nPolicy '" + $Policy.Name + "':") -ForegroundColor Yellow
            Write-Host ("   - Type: '" + $Cmdlets[$Cmdlet] + "'.") -ForegroundColor DarkCyan
            Write-Host ("   - State: " + $Policy.State + ".") -ForegroundColor DarkCyan
            Write-Host ("   - Issues: ") -ForegroundColor Red
            foreach ($Issue in $Issues) {
                Write-Host ("      -> " + $Issue) -ForegroundColor DarkCyan
                $IssueCounter += 1
            }
        }
    }
}
if ($IssueCounter -eq 0) {
    Write-Host ("`nNo logical inconsistencies found!") -ForegroundColor DarkGreen
}
Write-Output "`n"
