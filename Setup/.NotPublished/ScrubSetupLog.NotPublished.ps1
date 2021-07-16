# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#This script is to take the last part of the setup log and take out all the content that we need to run Pester Testing
#It will then change typical values that we see/need to lab values so it can be in the project.
#Error Context might not be scrubbed properly
[CmdletBinding()]
param(
    [System.IO.FileInfo]$SetupLog
)


Function Get-EvaluatedSettingOrRule {
    param(
        [string]$SettingName,
        [string]$SettingOrRule = "Setting"
    )
    return Select-String ("Evaluated \[{0}:{1}\].+\[Value:" -f $SettingOrRule, $SettingName) $SetupLog | Select-Object -Last 1
}

Function Add-SettingOrRuleToCollect {
    param(
        [string]$Name,
        [string]$SettingOrRule = "Setting"
    )
    return [PSCustomObject]@{
        SettingOrRule = $SettingOrRule
        Name          = $Name
    }
}

$settingOrRulesToCollect = @{
    PendingRebootWindowsComponents = (Add-SettingOrRuleToCollect -Name "PendingRebootWindowsComponents" -SettingOrRule "Rule")
    SchemaAdmin                    = (Add-SettingOrRuleToCollect -Name "SchemaAdmin")
    EnterpriseAdmin                = (Add-SettingOrRuleToCollect -Name "EnterpriseAdmin")
    ExOrgAdmin                     = (Add-SettingOrRuleToCollect -Name "ExOrgAdmin")
}

$selectStringToCollectRequired = @{
    SchemaUpdate       = "Schema Update Required Status : '(\w+)'."
    OrgConfigUpdate    = "Organization Configuration Update Required Status : '(\w+)'."
    DomainConfigUpdate = "Domain Configuration Update Required Status : '(\w+)'."
    LoggedOnUser       = "Logged on user: (.+)."
    ComputerFQdn       = "Evaluated \[Setting:ComputerNameDnsFullyQualified\]"
}

$selectStringToCollectIfCan = @{
    LocalInstall  = "The locally installed version is (.+)\."
    BackupInstall = "The backup copy of the previously installed version is '(.+)'\."
}

$Script:validSetupLog = Select-String "Starting Microsoft Exchange Server \d\d\d\d Setup" $SetupLog -Context 1, 200 | Select-Object -Last 1

if ($null -eq $validSetupLog) {
    throw "Failed to provide valid Exchange Setup Log"
}

$logContent = New-Object 'System.Collections.Generic.List[string]'
$Script:scrubbedValues = New-Object 'System.Collections.Generic.List[string]'

$logContent.Add($validSetupLog.Context.PreContext)
$logContent.Add($validSetupLog.Line)

foreach ($line in $validSetupLog.Context.PostContext) {
    if ($line.Trim().EndsWith("] **************")) {
        $logContent.Add($line)
        break
    }
    $logContent.Add($line)
}

#Check to see if we have our main strings we want.
foreach ($key in $selectStringToCollectRequired.Keys) {
    $result = $logContent | Select-String $selectStringToCollectRequired[$key]

    if ($null -eq $result) {
        #try to find it.
        $result = Select-String $selectStringToCollectRequired[$key] $SetupLog | Select-Object -Last 1

        if ($null -eq $result -and
            $result.LineNumber -lt $validSetupLog.LineNumber) {
            throw "Failed to find $key"
        }

        $logContent.Add($result.Line)
    }
}

foreach ($key in $selectStringToCollectIfCan.Keys) {
    $result = $logContent | Select-String $selectStringToCollectIfCan[$key]

    if ($null -eq $result) {
        Write-Output "Failed to find $key"
    }
}

#add the other things we want or need.
foreach ($key in $settingOrRulesToCollect.Keys) {

    $result = Get-EvaluatedSettingOrRule -SettingOrRule ($settingOrRulesToCollect[$key].SettingOrRule) -SettingName ($settingOrRulesToCollect[$key].Name)

    if ($null -ne $result -and
        $result.LineNumber -gt $validSetupLog.LineNumber) {

        if (!$logContent.IndexOf($result.Line)) {
            $logContent.Add($result.Line)
        }
    } else {
        #can't do a throw as we might have a second attempt run where we don't have some of these values
        Write-Output "Failed to find $key"
    }
}

$allContent = [IO.File]::ReadAllLines($SetupLog.FullName)
$i = $allContent.Count - 500
while ($i -lt $allContent.Count) {
    $logContent.Add($allContent[$i++])
}

Function ScrubValuesAndReplace {
    param(
        [string]$Match,
        [string]$Replace
    )

    $content = $Script:logContent
    $newContent = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in $content) {
        $newContent.Add($line.Replace($Match, $Replace, [System.StringComparison]::InvariantCultureIgnoreCase))
    }

    $script:scrubbedValues.Add($Match)
    $Script:logContent = $newContent
}

$scrubToDomainPossibleName = "Rey.Ben.Skywalker.Child.Solo.local"

#Scrub the data
$loggedOnUserSls = $logContent | Select-String "Logged on user: (.+)."

if ($null -eq $loggedOnUserSls) { throw "Missing logged on user" }

$loggedOnUser = $loggedOnUserSls.Matches.Groups[1].Value
ScrubValuesAndReplace -Match $loggedOnUser -Replace "SOLO\Han"

$domainControllerSls = $logContent | Select-String "The MSExchangeADTopology has a persisted domain controller: (.+)"

if ($null -eq $domainControllerSls) {

    $domainControllerSls = $logContent | Select-String "PrepareAD has been run, and has replicated to this domain controller; so setup will use (.+)"

    if ($null -eq $domainControllerSls) {
        $domainControllerSls = $logContent | Select-String "Setup has chosen the local domain controller (.+) for initial queries"
    }

    if ($null -eq $domainControllerSls) { throw "Missing Domain Controller" }
}

$domainControllerTemp = $domainControllerSls.Matches.Groups[1].Value
$domainControllerSplit = $domainControllerTemp.Split(".")
$i = 1
$domainController = [string]::Empty

while ($i -le $domainControllerSplit.Count) {

    if ($i -eq $domainControllerSplit.Count) {
        $domainController = "DC1$domainController"
    } else {
        $domainController = ".$($scrubToDomainPossibleName.Split(".")[-$i])$domainController"
    }
    $i++
}

$domainController = $domainController.TrimEnd(".")
ScrubValuesAndReplace -Match $domainControllerTemp -Replace $domainController

$configurationContainerSls = $logContent | Select-String "Exchange configuration container for the organization is 'CN=Microsoft Exchange,CN=Services,(.+)'\."
$configurationContainer = [string]::Empty
$i = 1
$configurationContainerSplit = $configurationContainerSls.Matches.Groups[1].Value.Split(",")

while ($i -le $configurationContainerSplit.Count) {

    if ($i -ne $configurationContainerSplit.Count) {
        $configurationContainer = ",DC=$($scrubToDomainPossibleName.Split(".")[-$i])$configurationContainer"
    } else {
        $configurationContainer = "CN=Configuration$configurationContainer"
    }
    $i++
}

ScrubValuesAndReplace -Match $configurationContainerSls.Matches.Groups[1].Value -Replace $configurationContainer

$orgContainerSls = $logContent | Select-String "Exchange organization container for the organization is 'CN=(.+),CN=Microsoft Exchange,CN=Services,CN=Configuration,(.+)'\."
$index = $orgContainerSls.Line.IndexOf("'CN=") + 1
$orgContainerMatch = $orgContainerSls.Line.Substring($index, $orgContainerSls.Line.Length - $index - 2)
$orgContainer = $orgContainerMatch.Replace($orgContainerSls.Matches.Groups[1].Value, "SoloORG")

ScrubValuesAndReplace -Match $orgContainerMatch -Replace $orgContainer
ScrubValuesAndReplace -Match $orgContainersls.Matches.Groups[1].Value -Replace "SoloORG"

$serverFQDNSls = $logContent | Select-String "Evaluated \[Setting:ComputerNameDnsFullyQualified\].+\[Value:`"(.+)`"\] \[ParentValue:"
$i = 1
$serverFqdnMatch = $serverFQDNSls.Matches.Groups[1].Value
$serverFqdnSplit = $serverFqdnMatch.Split(".")
$serverFqdn = [string]::Empty

while ($i -le $serverFqdnSplit.Count) {

    if ($i -eq $serverFqdnSplit.Count) {
        $serverFqdn = "ExSvr1$serverFqdn"
    } else {
        $serverFqdn = ".$($scrubToDomainPossibleName.Split(".")[-$i])$serverFqdn"
    }
    $i++
}

ScrubValuesAndReplace -Match $serverFqdnMatch -Replace $serverFqdn
ScrubValuesAndReplace -Match $serverFqdnSplit[0] -Replace "ExSvr1"

#Possible Schema Master
$schemaMasterSls = $logContent | Select-String "Setup will attempt to use the Schema Master domain controller (.+)"

if ($null -ne $schemaMasterSls) {
    $schemaMasterMatch = $schemaMasterSls.Matches.Groups[1].Value
    $schemaMasterSplit = $schemaMasterMatch.Split(".")
    $i = 1
    $schemaMaster = [string]::Empty

    while ($i -le $schemaMasterSplit.Count) {

        if ($i -eq $schemaMasterSplit.Count) {
            $schemaMaster = "SchemaMaster$SchemaMaster"
        } else {
            $schemaMaster = ".$($scrubToDomainPossibleName.Split(".")[-$i])$schemaMaster"
        }
        $i++
    }
    ScrubValuesAndReplace -Match $schemaMasterMatch -Replace $schemaMaster
    ScrubValuesAndReplace -Match $schemaMasterSplit[0] -Replace "SchemaMaster"
}

#Other possible DCs
$possibleDomainControllersSls = $logContent | Select-String "Previous operation run on domain controller '(.+)'\."

if ($null -ne $possibleDomainControllersSls) {

    $serversList = @()

    foreach ($sls in $possibleDomainControllersSls) {

        if (!$serversList.Contains($sls.Matches.Groups[1].Value)) {
            $serversList += $sls.Matches.Groups[1].Value
        }
    }

    $iCount = 2
    foreach ($server in $serversList) {
        $i = 1
        $serverReplace = [string]::Empty
        $serverSplit = $server.Split(".")

        while ($i -le $serverSplit.Count) {

            if ($i -eq $serverSplit.Count) {
                $serverReplace = "DC$iCount$serverReplace"
                $serverNameReplace = "DC$iCount"
                $iCount++
            } else {
                $serverReplace = ".$($scrubToDomainPossibleName.Split(".")[-$i])$serverReplace"
            }

            $i++
        }

        ScrubValuesAndReplace -Match $server -Replace $serverReplace
        ScrubValuesAndReplace -Match $serverSplit[0] -Replace $serverNameReplace
    }
}

Write-Output $Script:scrubbedValues
$outFile = $SetupLog.FullName.Replace($SetupLog.Extension, ".Scrubbed$($SetupLog.Extension)")
$logContent | Out-File -FilePath $outFile
