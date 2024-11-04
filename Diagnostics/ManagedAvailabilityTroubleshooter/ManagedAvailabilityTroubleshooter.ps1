# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Managed Availability Troubleshooter
# The goal of this script is to more easily investigate issues related of Managed Availability

#  Provide your feedback to ExToolsFeedback@microsoft.com
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Override for now')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('CustomRules\AvoidUsingReadHost', '', Justification = 'Do not want to change logic of script as of now')]
[CmdletBinding()]
param([string]$pathForLogs, [switch]$Collect , [switch] $AllServers , [switch] $OnlyThisServer , [switch]$Help)

$Script:lastProbeError = $null
$Script:foundIssue = $false
$Script:checkForKnownIssue = $false
$Script:KnownIssueDetectionAlreadyDone = $false
$Script:LoggingMonitoringPath = ""

function TestFileOrCmd {
    [CmdletBinding()]
    param( [String] $FileOrCmd )

    if ($FileOrCmd -like "File missing for this action*") {
        Write-Host -ForegroundColor red $FileOrCmd
        exit
    }
}

function ParseProbeResult {
    [CmdletBinding()]
    param( [String] $FilterXpath , [String] $MonitorToInvestigate , [String] $ResponderToInvestigate)

    TestFileOrCmd $ProbeResultEventCmd
    ParseProbeResult2 -ProbeResultEventCompleteCmd ($ProbeResultEventCmd + " -MaxEvents 200" ) `
        -FilterXpath $FilterXpath `
        -WaitString "Parsing only last 200 probe events for quicker response time" `
        -MonitorToInvestigate $MonitorToInvestigate `
        -ResponderToInvestigate $ResponderToInvestigate
    if ("yes", "YES", "Y", "y" -contains (Read-Host ("`nParsed last 200 probe events for quicker response.`nDo you like to parse all probe events ? Y/N (default is ""N"")"))) {
        ParseProbeResult2 -ProbeResultEventCompleteCmd $ProbeResultEventCmd `
            -FilterXpath $FilterXpath `
            -WaitString "Parsing all probe events. this may be slow as there is lots of events" `
            -MonitorToInvestigate $MonitorToInvestigate `
            -ResponderToInvestigate $ResponderToInvestigate
    }
}

function ParseProbeResult2 {
    [CmdletBinding()]
    param( [String] $ProbeResultEventCompleteCmd , [String] $FilterXpath , [String] $WaitString , [String] $MonitorToInvestigate , [String] $ResponderToInvestigate)

    TestFileOrCmd $ProbeResultEventCmd
    $ProbeEventsCmd = '(' + $ProbeResultEventCompleteCmd + ' -FilterXPath ("' + $FilterXpath + '") -ErrorAction SilentlyContinue | % {[XML]$_.toXml()}).event.userData.eventXml'
    Write-Verbose $ProbeEventsCmd
    $titleProbeEvents = "Probe events"
    if ( $ProbeDetailsFullName )
    {	$titleProbeEvents = $ProbeDetailsFullName + " events" }
    if ($WaitString) {
        Write-Progress "Checking Probe Result Events" -Status $WaitString
    } else {
        Write-Progress "Checking Probe Result Events"
    }
    $checkErrorCount = $error.count
    $ProbeEvents = Invoke-Expression $ProbeEventsCmd
    Write-Progress "Checking Probe Result Events" -Completed
    $checkErrorCount = $error.count - $checkErrorCount
    if ($checkErrorCount -gt 0) {
        for ($j = 0; $j -lt $checkErrorCount; $j++) {
            if ($error[$j].FullyQualifiedErrorId -like "NoMatchingEventsFound*")
            { Write-Host -foreground red "No events were found" }
            else
            { Write-Host -foreground red $error[$j].exception.message }
        }
    }
    if ($ProbeEvents) {
        foreach ($ProbeEvt in $ProbeEvents) {
            if ($ProbeEvt.ResultType -eq 4) {
                $Script:lastProbeError = $ProbeEvt
                if ($Script:KnownIssueDetectionAlreadyDone -eq $false) { KnownIssueDetection $MonitorToInvestigate $ResponderToInvestigate }
                break
            }
        }
        if ($Script:KnownIssueDetectionAlreadyDone -eq $false) { KnownIssueDetection $MonitorToInvestigate $ResponderToInvestigate }
        $ProbeEvents | Select-Object -Property @{n = "ExecutionStartTime (GMT)"; e = { $_.ExecutionStartTime } }, @{n = "ExecutionEndTime (GMT)"; e = { $_.ExecutionEndTime } }, @{n = 'ResultType'; e = { $_.ResultType -replace "1", "Timeout" -replace "2", "Poisoned" -replace "3", "Succeeded" -replace "4", "Failed" -replace "5", "Quarantined" -replace "6", "Rejected" } }, @{n = 'Error'; e = { $_.Error -replace "`r`n", "`r" } }, @{n = 'Exception'; e = { $_.Exception -replace "`r`n", "`r" } }, FailureContext, @{n = 'ExecutionContext'; e = { $_.ExecutionContext -replace "`r`n", "`r" } }, RetryCount, ServiceName, ResultName, StateAttribute* | Out-GridView -Title $titleProbeEvents
    }
    if ($Script:KnownIssueDetectionAlreadyDone -eq $false) { KnownIssueDetection $MonitorToInvestigate $ResponderToInvestigate }
}

function InvestigateProbe {
    [CmdletBinding()]
    param([String]$ProbeToInvestigate , [String]$MonitorToInvestigate , [String]$ResponderToInvestigate , [String]$ResourceNameToInvestigate , [String]$ResponderTargetResource )

    TestFileOrCmd $ProbeDefinitionEventCmd
    if (-not ($ResponderTargetResource) -and ($ProbeToInvestigate.split("/").Count -gt 1)) {
        $ResponderTargetResource = $ProbeToInvestigate.split("/")[1]
    }
    $ProbeDetailsCmd = '(' + $ProbeDefinitionEventCmd + '| % {[XML]$_.toXml()}).event.userData.eventXml| ? {$_.Name -like "' + $ProbeToInvestigate.split("/")[0] + '*" }'
    Write-Verbose $ProbeDetailsCmd
    Write-Progress "Checking Probe definition"
    $ProbeDetails = Invoke-Expression $ProbeDetailsCmd
    Write-Progress "Checking Probe definition" -Completed
    if ( $ProbeDetails) {
        if ($ProbeDetails.Count -gt 1) {
            if ($ResourceNameToInvestigate) {
                $ProbeDetailsForSelectedResourceName = $ProbeDetails | Where-Object { $_.TargetResource -eq $ResourceNameToInvestigate }
                if ($ProbeDetailsForSelectedResourceName )
                { $ProbeDetails = $ProbeDetailsForSelectedResourceName }
            }
            if ($ProbeDetails.Count -gt 1) {
                if ($ResponderTargetResource) {
                    $ProbeDetailsForSelectedResourceName = $ProbeDetails | Where-Object { $_.TargetResource -eq $ResponderTargetResource }
                    if ($ProbeDetailsForSelectedResourceName )
                    { $ProbeDetails = $ProbeDetailsForSelectedResourceName }
                }

                if ($ProbeDetails.Count -gt 1) {
                    Write-Host -ForegroundColor red ("Found no probe for " + $ResourceNameToInvestigate + " TargetResource")
                    Write-Host "`nSelected all possible Probes in this list: "
                    if ($ProbeDetails.Count -gt 20) {
                        Write-Host -ForegroundColor red ("more than 30 Probes in the list. Keeping only the 30 first probes")
                        $ProbeDetails = $ProbeDetails[0..19]
                    }
                }
            }
        }
        $ProbeDetails | Format-List *
        $ProbeDetailsFullName = $null
        foreach ($ProbeInfo in $ProbeDetails) {
            $probeName2add = $ProbeInfo.Name
            if ($ProbeInfo.TargetResource) {
                if ( -not ($ProbeInfo.TargetResource -eq "[null]"))
                { $probeName2add += "/" + $ProbeInfo.TargetResource }
            }
            if ($null -eq $ProbeDetailsFullName)
            { $ProbeDetailsFullName = $probeName = $probeName2add }
            else {
                $probeNameAlreadyInTheList = $false
                foreach ( $PresentProbeName in ($probeName -replace " and ", ";").split(";")) {
                    if ($PresentProbeName -eq $probeName2add)
                    { $probeNameAlreadyInTheList = $true }
                }
                if ($probeNameAlreadyInTheList -eq $false) {
                    $ProbeDetailsFullName += "' or ResultName='" + $probeName2add
                    $probeName += " and " + $probeName2add
                }
            }
        }

        if ($MonitorToInvestigate) {
            $relationDescription = "`n" + $probeName + " errors can result in the failure of " + $MonitorToInvestigate + " monitor"
            if ( $ResponderToInvestigate) {
                $relationDescription +=	" which triggered " + $ResponderToInvestigate
            }
            Write-Host $relationDescription
        }
        if ( $probeName -eq "EacBackEndLogonProbe") {
            if ($Script:KnownIssueDetectionAlreadyDone -eq $false) { KnownIssueDetection $MonitorToInvestigate $ResponderToInvestigate }

            $EacBackEndLogonProbeFolder = $Script:LoggingMonitoringPath + "\ECP\EacBackEndLogonProbe"
            if ( Test-Path $EacBackEndLogonProbeFolder) {
                $EacBackEndLogonProbeFile = Get-ChildItem ($EacBackEndLogonProbeFolder) | Select-Object -Last 1
                if ($EacBackEndLogonProbeFile) {
                    Write-Host "found and opening EacBackEndLogonProbe log / check the file for further error details"
                    notepad $EacBackEndLogonProbeFile.FullName
                }
            } else
            { Write-Host -ForegroundColor red ("Missing logs from path $EacBackEndLogonProbeFolder ") }
        } else {
            ParseProbeResult -FilterXpath ("*[UserData[EventXML[ResultName='" + $ProbeDetailsFullName + "']]]") `
                -MonitorToInvestigate $MonitorToInvestigate `
                -ResponderToInvestigate $ResponderToInvestigate
        }
    } else
    { Write-Host("`nFound no definitions for " + $ProbeToInvestigate + " probe") }
}

function InvestigateMonitor {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '', Justification = 'Override for now')]
    [CmdletBinding()]
    param( [String]$MonitorToInvestigate , [String]$ResourceNameToInvestigate , [String]$ResponderTargetResource , [String] $ResponderToInvestigate)

    if ($MonitorToInvestigate -like "MaintenanceFailureMonitor*") {
        $MaintenanceFailureMonitor = $MonitorToInvestigate.split(".")[1]
        Write-Host ("`nThis is triggered by MaintenanceFailureMonitor " + $MaintenanceFailureMonitor)
        InvestigateMaintenanceMonitor $MaintenanceFailureMonitor $ResponderToInvestigate
        break
    }

    TestFileOrCmd $MonitorDefinitionCmd
    $MonitorDetailsCmd = '(' + $MonitorDefinitionCmd + '| % {[XML]$_.toXml()}).event.userData.eventXml| ? {$_.Name -like "' + $MonitorToInvestigate.split("/")[0] + '*" }'
    Write-Verbose $MonitorDetailsCmd
    Write-Progress "Checking Monitor definition"
    $MonitorDetails = Invoke-Expression $MonitorDetailsCmd | Select-Object -uniq
    Write-Progress "Checking Monitor definition" -Completed
    if ($MonitorDetails.Count -gt 1) {
        if ( $ResourceNameToInvestigate ) {
            $MonitorDetailsForSelectedResourceName = $MonitorDetails | Where-Object { $_.TargetResource -eq $ResourceNameToInvestigate }
            if ($MonitorDetailsForSelectedResourceName)
            { $MonitorDetails = $MonitorDetailsForSelectedResourceName }
        }
        if ($MonitorDetails.Count -gt 1) {
            if ($ResponderTargetResource) {
                $MonitorDetailsForSelectedResourceName = $MonitorDetails | Where-Object { $_.TargetResource -eq $ResponderTargetResource }
                if ($MonitorDetailsForSelectedResourceName)
                { $MonitorDetails = $MonitorDetailsForSelectedResourceName }
            }
            if ($MonitorDetails.Count -gt 1) {
                Write-Host -ForegroundColor yellow ("Found multiple monitors , select the Monitor you like to investigate")
                $MonitorDetailsChosen = $MonitorDetails | Select-Object -Property name, TargetResource, SampleMask | Group-Object SampleMask
                $NumberOfGroupsOfSampleMask = 0; $MonitorDetailsChosen | ForEach-Object { $NumberOfGroupsOfSampleMask ++ }; $NumberOfGroupsOfSampleMask
                if ($NumberOfGroupsOfSampleMask -gt 1) {
                    Write-Host "`nMultiple Monitor, Select the Monitor you like to investigate"
                    $MonitorDetailsChosen | Out-GridView -PassThru -Title "Multiple Monitor, Select the Monitor you like to investigate"
                } else
                { Write-Host -ForegroundColor yellow ("All Monitors have same SampleMask , thus using one of them to check related probe") }
                if ($MonitorDetailsChosen) {
                    $MonitorDetails = $MonitorDetails | Where-Object { $_.SampleMask -eq $MonitorDetailsChosen.Name } | Sort-Object -Unique
                }
            }

            if ($MonitorDetails.Count -gt 1) {
                Write-Host -ForegroundColor red ("Found no matching Monitor")
                exit
            }
        }
    }
    $MonitorDetails | Format-List *
    $ProbeToInvestigate = $MonitorDetails.SampleMask | Select-Object -uniq

    if ($ProbeToInvestigate) {
        if ($ProbeToInvestigate.Count -gt 1) {
            Write-Host ("`nMultiple probes linked with the monitor " + $MonitorToInvestigate + " , here is the list : " + $ProbeToInvestigate)
            foreach ($individualProbeToInvestigate in $ProbeToInvestigate) {
                InvestigateProbe -ProbeToInvestigate $individualProbeToInvestigate `
                    -MonitorToInvestigate $MonitorToInvestigate `
                    -ResponderToInvestigate $ResponderToInvestigate `
                    -ResourceNameToInvestigate $ResourceNameToInvestigate `
                    -ResponderTargetResource $ResponderTargetResource
            }
        } else {
            Write-Host ("`nThe probe triggering " + $MonitorToInvestigate + " monitor is " + $ProbeToInvestigate)
            InvestigateProbe -ProbeToInvestigate $ProbeToInvestigate `
                -MonitorToInvestigate $MonitorToInvestigate `
                -ResponderToInvestigate $ResponderToInvestigate `
                -ResourceNameToInvestigate $ResourceNameToInvestigate `
                -ResponderTargetResource $ResponderTargetResource
        }
    } else
    { Write-Host ("`nFound no probe triggering " + $MonitorToInvestigate ) }
}

function InvestigateMaintenanceMonitor {
    [CmdletBinding()]
    param([String]$MaintenanceFailureMonitor , [String] $ResponderToInvestigate)

    TestFileOrCmd $MaintenanceDefinitionCmd
    $MaintenanceDefinitionCmd = '(' + $MaintenanceDefinitionCmd + '| % {[XML]$_.toXml()}).event.userData.eventXml| ? {$_.ServiceName -like "' + $MaintenanceFailureMonitor + '*" }'
    Write-Verbose $MaintenanceDefinitionCmd
    Write-Progress "Checking Maintenance definition"
    $MaintenanceDetails = Invoke-Expression $MaintenanceDefinitionCmd
    Write-Progress "Checking Maintenance definition" -Completed
    if ( $MaintenanceDetails) {
        $MaintenanceDetailsGroups = $MaintenanceDetails | Group-Object Name
        $NumberOfGroupsOfServiceName = 0; $MaintenanceDetailsGroups | ForEach-Object { $NumberOfGroupsOfServiceName ++ }
        if ($NumberOfGroupsOfServiceName -gt 1) {
            Write-Host "`nSelect the Maintenance you like to investigate"
            $MaintenanceDetailsGroups | Out-GridView -PassThru -Title "Multiple Monitor, Select the Monitor you like to investigate"
        }

        $MaintenanceDetails = $MaintenanceDetails | Where-Object { $_.Name -eq $MaintenanceDetailsGroups.Name } | Sort-Object -Unique

        $MaintenanceDetails | Format-List

        TestFileOrCmd $MaintenanceResultCmd
        $MaintenanceResultCmd = '(' + $MaintenanceResultCmd + ' -FilterXPath "*/System/Level<=3" | % {[XML]$_.toXml()}).event.userData.eventXml| ? {$_.ResultName -like "' + $MaintenanceDetails.Name + '*" }'
        Write-Verbose $MaintenanceResultCmd
        Write-Progress "Checking Maintenance Result warnings and errors"
        $MaintenanceResults = Invoke-Expression $MaintenanceResultCmd
        Write-Progress "Checking Maintenance Result warnings and errors"
        $Script:lastProbeError = $MaintenanceResults[0]
        if ($Script:KnownIssueDetectionAlreadyDone -eq $false) { KnownIssueDetection $MonitorToInvestigate $ResponderToInvestigate }
        $MaintenanceResults | Out-GridView -Title "Maintenance warnings and alerts"
    }
}

function OverrideIfNeeded {
    [CmdletBinding()]
    param( [String]$ResponderToInvestigate , [String]$ResponderServiceName)
    if ( -not ( $ResponderServiceName)) {
        Write-Host -foreground red ("`nFound no ServiceName for " + $ResponderToInvestigate + " Responder. Thus can't provide the override command to disable this responder if needed.")
        return
    }

    Write-Host ("`nThe Responder that triggered the RecoveryAction you selected is " + $ResponderToInvestigate + " .")
    Write-Host ("This action was taken to restore the service as soon as possible to end users.")
    Write-Host ("In case this recovery action happens too often or does not help , you may like to temporarily disable this failover response while you investigate.")

    $ResponderWithServiceName = $ResponderServiceName + "`\" + $ResponderToInvestigate
    $AddGlobalMonitoringOverrideCmd = "Add-GlobalMonitoringOverride -Identity $ResponderWithServiceName  -ItemType Responder -PropertyName Enabled -PropertyValue 0"
    $RemoveGlobalMonitoringOverrideCmd = "Remove-GlobalMonitoringOverride -Identity $ResponderWithServiceName  -ItemType Responder -PropertyName Enabled"
    if ( $pathForLogsSpecified ) {
        Write-Host ("If you like to disable " + $ResponderToInvestigate + " Responder , run this command in Exchange Powershell")
        Write-Host -foreground yellow $AddGlobalMonitoringOverrideCmd
        Write-Host -foreground yellow ("`nTo remove the override afterwards to enable " + $ResponderToInvestigate + " Responder again ,use the command:")
        Write-Host -foreground yellow $RemoveGlobalMonitoringOverrideCmd
    } else {
        if ("yes", "YES", "Y", "y" -contains (Read-Host ("Do you like to disable " + $ResponderToInvestigate + " Responder ? Y/N"))) {
            Write-Host ("`nHere is the command used to disable " + $ResponderToInvestigate + " Responder :")
            Write-Host -foreground yellow $AddGlobalMonitoringOverrideCmd
            Invoke-Expression $AddGlobalMonitoringOverrideCmd
            Write-Host ("It may take some time to apply the change to disable " + $ResponderToInvestigate + " Responder.")
            $continueToCheckIfResponderIsEnabled = $true
            while ( $continueToCheckIfResponderIsEnabled) {
                if ("yes", "YES", "Y", "y" -contains (Read-Host ("Do you like to check if " + $ResponderToInvestigate + " Responder is now disabled ? Y/N"))) {
                    TestFileOrCmd $ResponderDefinitionCmd
                    $ResponderDetailsCmd = '(' + $ResponderDefinitionCmd + '| % {[XML]$_.toXml()}).event.userData.eventXml| ? {$_.Name -eq "' + $ResponderToInvestigate + '" }'
                    Write-Verbose $ResponderDetailsCmd
                    Write-Progress "Checking Responder definition"
                    $ResponderDetails = Invoke-Expression $ResponderDetailsCmd
                    Write-Progress "Checking Responder definition" -Completed
                    if ($ResponderDetails) {
                        if ( $ResponderDetails.enabled -eq 1) {
                            Write-Host ("`n" + $ResponderToInvestigate + " Responder is currently still enabled.")
                            $ResponderDetails | Format-Table ServiceName, Name, Enabled -a
                            $MSExchangeHMservice = Get-Service MSExchangeHM
                            if ($MSExchangeHMservice) {
                                if (($MSExchangeHMservice).Status -eq "Stopped") {
                                    Write-Host ("`nThe Microsoft Exchange Health Manager service is stopped.")
                                    Write-Host ("As a result , all Exchange monitoring is currently disabled.")
                                    Write-Host ("The status of this responder will be calculated as disabled next time you start the Microsoft Exchange Health Manager service.")
                                } else {
                                    Write-Host ("It may take some time to apply the change to disable " + $ResponderToInvestigate + " Responder.")
                                    Write-Host ("You may wait a few minutes and check again.")
                                }
                            } else
                            { Write-Host ("`nCan't check the status of MSExchangeHM/Microsoft Exchange Health Manager service. If this service is not started , all Exchange monitoring is disabled.") }
                        } else {
                            Write-Host ("`n" + $ResponderToInvestigate + " Responder is now disabled and similar reboot should not currently be triggered by this responder")
                            $ResponderDetails | Format-Table ServiceName, Name, Enabled -a
                            Write-Host ("When you have fixed the issue triggering this responder, you can reenable it again using this command :")
                            Write-Host ("remove-GlobalMonitoringOverride -Identity " + $ResponderWithServiceName + "  -ItemType Responder -PropertyName Enabled")
                            $continueToCheckIfResponderIsEnabled = $false
                        }
                    } else
                    { Write-Host ("`nFound no events related to " + $ResponderToInvestigate + " Responder. If you have restarted Microsoft Exchange Health Manager service recently , this is probably normal and you have to wait for the service to rediscover the responders") }
                } else
                { $continueToCheckIfResponderIsEnabled = $false }
            }
            Write-Host -foreground yellow ("`nTo remove the override afterwards to enable " + $ResponderToInvestigate + " Responder again , use this command:")
            Write-Host -foreground yellow $RemoveGlobalMonitoringOverrideCmd
            Read-Host ("Take note of this command to remove the override afterwards, then type enter to continue")
        }
    }
}

function InvestigateResponder {
    [CmdletBinding()]
    param( [String]$ResponderToInvestigate , [String]$ResourceNameToInvestigate )

    if ($ResponderToInvestigate -eq "ManagedAvailabilityStartup") {
        Write-Host "`nManagedAvailabilityStartup means HealthManager can't find the information about the Responder which triggered this reboot."
        Write-Host "`nSuch events can be seen when Exchange Server 2013 was rebooted."
        Write-Host "`nThis can happen as well when there is a blueScreen not triggered by Managed Availability , for example in case of Hanged I/O : https://technet.microsoft.com/en-us/library/ff625233(v=exchg.141).aspx"
        Write-Host "`nIn case it is a reboot , there can be related 1074 events in system log showing that a user forced a rebooted around that time."
        Write-Host "looking for 1074 events ..."

        TestFileOrCmd $SystemCmd
        $SystemCmd = $SystemCmd + ' -FilterXPath ("*[System[(EventID=''1074'')]]")'
        Write-Verbose $SystemCmd
        trap [System.Exception] { continue }
        $1074events = Invoke-Expression $SystemCmd
        if ($1074events.Count -eq 0)
        { Write-Host ("Found no 1074 events in system log") }
        else {
            Write-Host ("Found 1074 events in system log :")
            $1074events | Format-List
        }
    } else {
        TestFileOrCmd $ResponderDefinitionCmd
        $ResponderDetailsCmd = '(' + $ResponderDefinitionCmd + '| % {[XML]$_.toXml()}).event.userData.eventXml| ? {$_.Name -eq "' + $ResponderToInvestigate + '" }'
        Write-Verbose $ResponderDetailsCmd
        Write-Progress "Checking Responder definition"
        $ResponderDetails = Invoke-Expression $ResponderDetailsCmd | Select-Object -uniq
        Write-Progress "Checking Responder definition" -Completed
        if ( $ResponderDetails) {
            if ($ResponderDetails.Count -gt 1) {
                if ($ResourceNameToInvestigate) {
                    $ResponderDetailsForSelectedResourceName = $ResponderDetails | Where-Object { $_.TargetResource -eq $ResourceNameToInvestigate }
                    if ($ResponderDetailsForSelectedResourceName)
                    { $ResponderDetails = $ResponderDetailsForSelectedResourceName }
                    if ($ResponderDetails.Count -gt 1) {
                        $ResponderDetailsForSelectedResourceName = $ResponderDetails | Where-Object { $_.TargetExtension -eq $ResourceNameToInvestigate }
                        if ($ResponderDetailsForSelectedResourceName)
                        { $ResponderDetails = $ResponderDetailsForSelectedResourceName }
                    }
                }
                if ($ResponderDetails.Count -gt 1) {
                    Write-Host -ForegroundColor red ("Found no " + $ResponderToInvestigate + " Responder for " + $ResourceNameToInvestigate + " TargetResource")
                    Write-Host "Select the responder you like to investigate"
                    Start-Sleep -s 1
                    $ResponderChosen = $ResponderDetails | Out-GridView -PassThru -Title "Select the responder you like to investigate"
                    if ($ResponderChosen) {
                        if ($ResponderChosen.Count -gt 1 )
                        { $ResponderDetails = $ResponderChosen[0] }
                        else
                        { $ResponderDetails = $ResponderChosen }
                    } else {
                        Write-Host -ForegroundColor red ("No responder selected")
                        exit
                    }
                }
            }

            if ( $ResponderDetails.enabled -eq 1) {
                OverrideIfNeeded $ResponderToInvestigate $ResponderDetails.ServiceName
            } else {
                Write-Host ("`n" + $ResponderToInvestigate + " Responder is already disabled and similar reboot should not currently be triggered by this responder.")
                $ResponderDetails | Format-Table ServiceName, Name, Enabled -a
            }

            Write-Host ("`n" + $ResponderToInvestigate + " Responder properties :")
            $ResponderDetails | Format-List *
            $MonitorToInvestigate = $ResponderDetails.AlertMask
            if ($MonitorToInvestigate) {
                Write-Host ("`nThe monitor triggering " + $ResponderToInvestigate + " Responder is " + $MonitorToInvestigate)
                InvestigateMonitor -MonitorToInvestigate $MonitorToInvestigate `
                    -ResourceNameToInvestigate $ResourceNameToInvestigate `
                    -ResponderTargetResource $ResponderDetails.TargetResource `
                    -ResponderToInvestigate $ResponderToInvestigate
            } else
            {	Write-Host ("`nFound no monitor triggering " + $ResponderToInvestigate + "`n" ) }
            if ($Script:KnownIssueDetectionAlreadyDone -eq $false) { KnownIssueDetection $null $ResponderToInvestigate }
        } else
        { Write-Host ("`nFound no responder properties for the responder " + $ResponderToInvestigate ) }
    }
}

function KnownIssueDetection {
    [CmdletBinding()]
    param( [String]$MonitorToInvestigate , [String]$ResponderToInvestigate)

    if ($MonitorToInvestigate -or $ResponderToInvestigate) {
        Write-Host "`nKnown Issue Detection :"
        Write-Host "------------------------`n"
        if ($MonitorToInvestigate) { CheckIfThisCanBeAKnownIssueUsingMonitor $MonitorToInvestigate }
        if ($ResponderToInvestigate) { CheckIfThisCanBeAKnownIssueUsingResponder $ResponderToInvestigate }
        if ( $Script:foundIssue -eq $false) {
            Write-Host "Found no known issue in this script matching this monitor"
        } else {
            Write-Host -foreground yellow ("`n`nKnown issue found !! Please check the issue detected upper. To continue and check probe events anyway , press any key")
            $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        $Script:KnownIssueDetectionAlreadyDone = $true
    }
}

function CheckIfThisCanBeAKnownIssueUsingResponder {
    [CmdletBinding()]
    param( [String]$ResponderToInvestigate )

    $Script:checkForKnownIssue = $true
    if (($ResponderToInvestigate -eq "ActiveDirectoryConnectivityConfigDCServerReboot") -and ($MajorExchangeVersion -eq 15) -and ($MinorExchangeVersion -eq 0) -and ($BuildExchangeVersion -lt 775)) {
        Write-Host -foreground yellow ("There is a known issue with restarts initiated by the  ActiveDirectoryConnectivityConfigDCServerReboot prior to CU3 which appears to be your case" )
        Write-Host -foreground yellow ("Check https://support.microsoft.com/en-us/kb/2883203" )
        $Script:foundIssue = $true; return
    }

    if ($ResponderToInvestigate -eq "ImapProxyTestCafeOffline") {
        Write-Host -foreground yellow ("ImapProxyTestCafeOffline can set ImapProxy component as inactive when 127.0.0.1 is blocked in IMAP bindings." )
        Write-Host -foreground yellow ("Check ImapSettings using Exchange Powershell command : Get-ImapSettings." )
        Write-Host ("Change the settings if needed with Set-ImapSettings - https://technet.microsoft.com/en-us/library/aa998252(v=exchg.150).aspx")
        $Script:foundIssue = $true; return
    }
    if ($ResponderToInvestigate -eq "PopProxyTestCafeOffline") {
        Write-Host -foreground yellow ("PopProxyTestCafeOffline can set POPProxy component as inactive when 127.0.0.1 is blocked in POP bindings." )
        Write-Host -foreground yellow ("Check PopSettings using Exchange Powershell command : Get-POPSettings." )
        Write-Host -foreground yellow ("Change the settings if needed with Set-POPSettings - https://technet.microsoft.com/en-us/library/aa997154(v=exchg.150).aspx")
        $Script:foundIssue = $true; return
    }
    if (($ResponderToInvestigate -eq "OutlookMapiHttpSelfTestRestart") -and ($MajorExchangeVersion -eq 15) -and ($MinorExchangeVersion -eq 0) -and ($BuildExchangeVersion -lt 1130)) {
        Write-Host -foreground yellow ("There is a known issue with OutlookMapiHttpSelfTestRestart prior to CU10 ( for reference OfficeMain: 1541090)" )
        Write-Host -foreground yellow ("You may plan to apply CU10 : https://support.microsoft.com/en-us/kb/3078678" )
        $Script:foundIssue = $true; return
    }
}

function CheckIfThisCanBeAKnownIssueUsingMonitor {
    [CmdletBinding()]
    param( [String]$MonitorToInvestigate )

    $Script:checkForKnownIssue = $true
    if (($MonitorToInvestigate -like "*Mapi.Submit.Monitor") -and ($MajorExchangeVersion -eq 15) -and ($MinorExchangeVersion -eq 0)) {
        Write-Host -foreground yellow ("There is a known issue with Mapi.Submit.Monitor. This issue is fixed in CU11 ( OfficeMain: 1956332) " )
        $Script:foundIssue = $true; return
    }
    if (($MonitorToInvestigate -like "MaintenanceFailureMonitor.Network") -and ($MajorExchangeVersion -eq 15) -and ($MinorExchangeVersion -eq 0) -and ($BuildExchangeVersion -lt 1130)) {
        Write-Host -foreground yellow ("There is a known issue with MaintenanceFailureMonitor.Network/IntraDagPingProbe is fixed in CU10.( for reference OfficeMain: 2080370)" )
        Write-Host -foreground yellow ("You may plan to apply CU10 : https://support.microsoft.com/en-us/kb/3078678" )
        $Script:foundIssue = $true; return
    }
    if (($MonitorToInvestigate -like "MaintenanceFailureMonitor.ShadowService") -and ($MajorExchangeVersion -eq 15) -and ($MinorExchangeVersion -eq 1) ) {
        Write-Host -foreground yellow ("There is a known issue with MaintenanceFailureMonitor.ShadowService which fix will be included in Exchange 2016 CU5 and upper.( for reference OfficeMain: 142253)" )
        $Script:foundIssue = $true; return
    }

    if (($MonitorToInvestigate -like "EacBackEndLogonMonitor") -and ($MajorExchangeVersion -eq 15) -and ($MinorExchangeVersion -eq 1) ) {
        Write-Host -foreground yellow ("EacBackEndLogonMonitor has been seen unhealthy linked uninitialized culture on test mailboxes. You may run this command and check if this helps : get-mailbox -Monitoring -server $env:COMPUTERNAME | Set-MailboxRegionalConfiguration -Language En-US -TimeZone ""Pacific Standard Time""" )
        $Script:foundIssue = $true; return
    }

    if ($MonitorToInvestigate -like "ActiveSyncCTPMonitor") {
        $ActiveSyncCTPpossible401issue = $true
        if ($Script:lastProbeError) {
            if ($Script:lastProbeError.StateAttribute6 -ne 401)
            { $ActiveSyncCTPpossible401issue = $false }
        }
        if ($ActiveSyncCTPpossible401issue) {
            Write-Host ("ActiveSyncCTPMonitor can fail with error 401 when BasicAuthEnabled setting in get-ActiveSyncVirtualDirectory has been changed and set to `$false.  - KB 3125818" )
            Write-Host("If this is your case , Enable Basic Authentication again if possible using the command :`nSet-ActiveSyncVirtualDirectory -basicAuthEnabled `$true." )
            Write-Host("Or disable this monitor using an override :`nAdd-GlobalMonitoringOverride -Identity ActiveSync\ActiveSyncCTPMonitor  -ItemType Monitor -PropertyName Enabled -PropertyValue 0" )
            $Script:foundIssue = $true; return
        }
    }

    if ($MonitorToInvestigate -like "ActiveSyncDeepTestMonitor") {
        $ActiveSyncDeepTestPossibleIndexWasOutOfRangeIssue = $true
        if ($Script:lastProbeError) {
            if ($Script:lastProbeError.Error -like "*Index was out of range*")
            { Write-Host -foreground yellow "Index was out of range error in the probe`n" }
            else
            { $ActiveSyncDeepTestPossibleIndexWasOutOfRangeIssue = $false }
        }
        if ($ActiveSyncDeepTestPossibleIndexWasOutOfRangeIssue) {
            Write-Host ("ActiveSyncDeepTestMonitor can fail with Index was out of range error when no active database are found on the server" )
            Write-Host("If this is your case , disable this monitor with this command : " )
            Write-Host("Add-GlobalMonitoringOverride -Identity ActiveSync\ActiveSyncDeepTestMonitor  -ItemType Monitor -PropertyName Enabled -PropertyValue 0" )
            $Script:foundIssue = $true; return
        }
    }

    if ($MonitorToInvestigate -like "ServerOneCopyInternalMonitor*") {
        $ServerOneCopyInternalPossibleWMIIssue = $true
        if ($Script:lastProbeError) {
            if ($Script:lastProbeError.Exception -like "*Microsoft.Exchange.Monitoring.ActiveMonitoring.HighAvailability.Probes.ServiceMonitorProbe.GetCurrentSystemUpTime*")
            { Write-Host -foreground yellow "Found ProbeException in Microsoft.Exchange.Monitoring.ActiveMonitoring.HighAvailability.Probes.ServiceMonitorProbe.GetCurrentSystemUpTime`n" }
            else
            { $ServerOneCopyInternalPossibleWMIIssue = $false }
        }
        if ($ServerOneCopyInternalPossibleWMIIssue ) {
            Write-Host -foreground yellow "ServerOneCopyInternalMonitor is failing to request information via WMI in GetCurrentSystemUpTime."
            Write-Host -foreground yellow "WMI request failing should be : SELECT LastBootUpTime FROM Win32_OperatingSystem WHERE Primary='true'"
            Write-Host -foreground yellow "This may be investigated at WMI level looking for this request"
            Write-Host  -foreground yellow "This WMI request is planned to be replaced in future version higher than 15.00.1187.000 likely CU13 by direct Windows native call without going through WMI layer.( for reference OfficeMain:2908185)"
            $Script:foundIssue = $true; return
        }
    }
    if ($MonitorToInvestigate -like "ServiceHealthMSExchangeReplEndpointMonitor*") {
        $ServiceHealthMSExchangeReplEndpointPossibleDNSissue = $true
        if ($Script:lastProbeError) {
            if ($Script:lastProbeError.Exception -like "*because DNS didn't return any information.*")
            { Write-Host -foreground yellow "Found Exception pointing to DNS missing information`n" }
            else
            { $ServiceHealthMSExchangeReplEndpointPossibleDNSissue = $false }
        }
        if ($ServiceHealthMSExchangeReplEndpointPossibleDNSissue) {
            Write-Host -foreground yellow "ServiceHealthMSExchangeReplEndpointMonitor is failing due to missing DNS entry."
            Write-Host -foreground yellow "Make sure that the 'Register this connection's addresses in DNS' property is selected on the network adapter"
            Write-Host -foreground yellow "https://support.microsoft.com/en-us/kb/2969070"
            $Script:foundIssue = $true; return
        }
    }
    if ($MonitorToInvestigate -like "DiscoveryErrorReportMonitor*") {
        Write-Host -foreground yellow "DiscoveryErrorReportMonitor is Disabled by default and should not be enabled"
        $Script:foundIssue = $true; return
    }
    if ($Script:lastProbeError) {
        if ($Script:lastProbeError.Exception -like "*The underlying connection was closed*") {
            Write-Host -foreground yellow "This probe error message related to underlying connection closed has been seen when connection for loopback adapter has been blocked at lower level before reaching Exchange`n"
            Write-Host -foreground yellow "You can check in IIS Default Web Site /Actions pane / Bindings that `"All Unassigned`" is used and this has not been changed to only allow specific IP.`n"
            Write-Host -foreground yellow "This has been seen when blocking some TLS version using SecureProtocols registry key or through GPO.`n"
            Write-Host -foreground yellow "You can check if some TLS version are disabled under HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols (https://techcommunity.microsoft.com/t5/exchange-team-blog/exchange-server-tls-guidance-part-2-enabling-tls-1-2-and/ba-p/607761).`n"
            Write-Host -foreground yellow "You may also check if this is linked with antivirus or local firewall rules.`n"
            $Script:foundIssue = $true; return
        }
    }
}

function InvestigateUnhealthyMonitor {
    [CmdletBinding()]
    param([String]$ServerHealthFile )

    Write-Progress "Checking MonitorHealth"
    if ($pathForLogsSpecified) {
        TestFileOrCmd $ServerHealthFile
        if ( -not (Test-Path $ServerHealthFile))
        { Write-Host -ForegroundColor red ("Path to ServerHealth file is invalid : $ServerHealthFile"); exit }

        $myHealthEntryList = New-Object System.Collections.ArrayList
        $currentHealthEntry = New-Object -TypeName PSObject
        $firstLine = $true
        foreach ($line in (Get-Content $ServerHealthFile)) {
            $propName = $line.split(" ")[0]
            if ( -not $propName) { continue; }
            if ($propName -eq "SerializationData" -or $propName -eq "Result" -or $propName -eq "PSComputerName" -or $propName -eq "PSShowComputerName") { continue; }
            $newMonitor = $false
            if ($propName -eq "RunSpaceId") {
                if ($firstLine)
                { $firstLine = $false; continue }
                else
                {	$newMonitor = $true }
            } else {
                foreach ($prop in (Get-Member -InputObject $currentHealthEntry -MemberType NoteProperty))
                { if ($prop.Name -eq $propName) {	$newMonitor = $true } }
            }

            if ( $newMonitor) {
                if ($currentHealthEntry.alertValue ) {
                    if (-not ($currentHealthEntry.AlertValue.ToString() -eq "Healthy"))
                    { [void] $myHealthEntryList.Add($currentHealthEntry) }
                }
                $currentHealthEntry = New-Object -TypeName PSObject
            }
            if ($propName -eq "RunSpaceId")
            { continue }
            $propValue = ($line.split(":")[1]).split(" ")[1]
            if ($propValue) { $currentHealthEntry | Add-Member -Name $propName -Value $propValue -MemberType NoteProperty }
        }
    } else {
        TestFileOrCmd $ServerHealthCmd
        $ServerHealthCmd = $ServerHealthCmd + '|?{$_.AlertValue -ne "Healthy"}'
        Write-Verbose $ServerHealthCmd
        $myHealthEntryList = Invoke-Expression $ServerHealthCmd
    }
    Write-Progress "Checking MonitorHealth" -Completed

    if ( $myHealthEntryList.count -gt 0) {
        $SelectUnhealthyMonitor = "Select the Unhealthy Monitor that you like to investigate"
        Write-Host $SelectUnhealthyMonitor
        Start-Sleep -s 1
        $UnhealthyMonitorToInvestigate = $myHealthEntryList | Out-GridView -PassThru -Title $SelectUnhealthyMonitor
        if ( $UnhealthyMonitorToInvestigate) {
            if (([string]::Compare($UnhealthyMonitorToInvestigate.Server, $env:COMPUTERNAME, $true) -eq 0) -or ($pathForLogsSpecified)) {
                InvestigateMonitor -MonitorToInvestigate $UnhealthyMonitorToInvestigate.Name `
                    -ResourceNameToInvestigate $null `
                    -ResponderTargetResource $UnhealthyMonitorToInvestigate.TargetResource `
                    -ResponderToInvestigate $null
            } else {
                Write-Host -ForegroundColor yellow ("`nThe Monitor you select is regarding a different server : " + $UnhealthyMonitorToInvestigate.Server + " .")
                Write-Host -ForegroundColor yellow ("Run this script on this server directly to analyze this monitor further." )
            }
        } else {
            Write-Host ("`nYou have not selected any unhealthy monitor. Run the script again and select an occurrence" )
        }
    } else {
        Write-Host ("`nFound no unhealthy monitor." )
    }
}

function CollectMaLogs {
    [CmdletBinding()]
    param([String] $InvocationPath )
    try {
        $ExchangeServerInfo = Get-ExchangeServer -identity $env:COMPUTERNAME -status | Format-List
    } catch [System.Management.Automation.CommandNotFoundException] {
        Write-Host -ForegroundColor red "Exchange Powershell not loaded.`nYou likely ran the script inside Windows powershell. Run it again inside Exchange powershell"
        exit
    } catch {
        Write-Host -ForegroundColor red ($error[0] | Format-List -Force | Out-String)
        exit
    }

    $OutputPath = (Split-Path -Parent $InvocationPath) + "\LogsCollected"
    if (-not (Test-Path($OutputPath)))
    { New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null }
    if (-not (Test-Path($OutputPath)))
    { Write-Host "Failed to create $OutputPath to store logs collected"; exit }

    $ExchangeServerInfoFile = $OutputPath + "\" + $env:COMPUTERNAME + "_ExchangeServer_FL.TXT"
    $ExchangeServerInfo | Out-File $ExchangeServerInfoFile

    $GlobalMOverride = Get-GlobalMonitoringOverride
    $GlobalMonitoringOverrideFile = $OutputPath + "\GlobalMonitoringOverride.TXT"
    if ($GlobalMOverride.Count -ne 0) { $GlobalMOverride | Format-List > $GlobalMonitoringOverrideFile }

    $ServerMOverride = Get-serverMonitoringOverride -Server $env:COMPUTERNAME
    $ServerMOverrideFile = $OutputPath + "\serverMonitoringOverride.TXT"
    if ($ServerMOverride.Count -ne 0) { $ServerMOverride | Format-List > $ServerMOverrideFile }

    $ServerComponentStatesFile = $OutputPath + "\ServerComponentStates.TXT"
    reg query HKLM\SOFTWARE\Microsoft\ExchangeServer\v15\ServerComponentStates /s > $ServerComponentStatesFile

    Write-Progress "Collecting Get-ServerHealth"
    $ServerHealthFile = $OutputPath + "\" + $env:COMPUTERNAME + "_ServerHealth_FL.TXT"
    Get-ServerHealth -Identity $env:COMPUTERNAME | Format-List > $ServerHealthFile
    Write-Progress "Collecting Get-ServerHealth" -Completed

    $EventLogNames = wEvtUtil.exe el | Select-String "Microsoft-Exchange"
    $EventLogNames += "Application", "System"

    foreach ($EventLogName in $EventLogNames) {
        $progressEventLogMessage = "Collecting " + $EventLogName + " EventLog"
        Write-Progress $progressEventLogMessage
        $evtUtilCmd = $EventLogName -replace "/", ""
        $evtxPath = $OutputPath + '\' + $evtUtilCmd + '.evtx'
        if ((Test-Path($evtxPath)))
        { Remove-Item $evtxPath | Out-Null }
        wEvtUtil epl "$EventLogName" "$evtxPath"
        Write-Progress $progressEventLogMessage -Completed
    }
    $monitoringFolders = Get-ChildItem ( $env:exchangeInstallPath + "\Logging\Monitoring" ) -Recurse | Where-Object { $_.PSIsContainer -eq $True }
    foreach ($monitoringFolder in $monitoringFolders) {
        $logCollectionMonitoringFolder = $OutputPath + "\" + $monitoringFolder.FullName.Substring(($env:exchangeInstallPath + "\Logging\Monitoring").length)
        if (-not (Test-Path($logCollectionMonitoringFolder)))
        { New-Item -ItemType Directory -Force -Path $logCollectionMonitoringFolder | Out-Null }
        if (-not (Test-Path($logCollectionMonitoringFolder)))
        { Write-Host "Failed to create $logCollectionMonitoringFolder to store logs collected"; exit }

        $monitoringFiles = Get-ChildItem ( $monitoringFolder.FullName ) | Where-Object { $_.PSIsContainer -eq $false }
        if ($monitoringFolder.Name -eq "ActiveMonitoringTraceLogs")
        { $monitoringFiles = $monitoringFiles | Sort-Object LastAccessTime -Descending | Select-Object -First 2 }

        foreach ($monitoringFile in $monitoringFiles ) {
            Write-Progress ("Collecting " + $monitoringFile.FullName)
            Copy-Item $monitoringFile.FullName -Destination $logCollectionMonitoringFolder
            Write-Progress ("Collecting " + $monitoringFile.FullName) -Completed
        }
    }

    $HighAvailabilityFiles = Get-ChildItem ($env:exchangeInstallPath + "\Logging\HighAvailability") | Where-Object { $_.PSIsContainer -eq $false }
    $logHighAvailabilityFolder = $OutputPath + "\HighAvailability"
    if (-not (Test-Path($logHighAvailabilityFolder)))
    { New-Item -ItemType Directory -Force -Path $logHighAvailabilityFolder | Out-Null }
    if (-not (Test-Path($logHighAvailabilityFolder)))
    { Write-Host "Failed to create $logHighAvailabilityFolder to store HighAvailability logs collected"; exit }
    foreach ($HighAvailabilityFile in $HighAvailabilityFiles ) {
        Write-Progress ("Collecting " + $HighAvailabilityFile.FullName)
        Copy-Item $HighAvailabilityFile.FullName -Destination $logHighAvailabilityFolder
        Write-Progress ("Collecting " + $HighAvailabilityFile.FullName) -Completed
    }

    $zipFileName = (Split-Path -Parent $InvocationPath) + "\MALogs" + (Get-Date -UFormat "%Y%m%d%H%M%S") + ".zip"
    Write-Progress "Zipping the logs collected"
    Add-Type -Assembly System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($OutputPath, $zipFileName, [System.IO.Compression.CompressionLevel]::Optimal, $false)
    Write-Progress "Zipping Log Collected" -Completed
    Write-Host ("You can delete the temporary directory " + $OutputPath)
    Write-Host ("The logs have been zipped in " + $zipFileName)
    exit
}

$ScriptUsage = "Run this script without parameter using Exchange Powershell to do the analysis on the Exchange server directly or collect the logs for analysis (option C in the menu).`nUse this link for the documentation http://blogs.technet.com/b/jcoiffin/archive/2015/10/21/troubleshoot-exchange-2013-2016-managed-availability.aspx"
if ($Help) {
    Write-Host $ScriptUsage
    exit
}

if ($PSVersionTable.PSVersion.Major -lt 3) {
    Write-Host -ForegroundColor red ("Current powershell version is " + $PSVersionTable.PSVersion.Major)
    Write-Host ("Upgrade to powershell 3 or higher to run this script")
    Write-Host ("Here is the link to download powershell version 4 : http://www.microsoft.com/en-US/download/details.aspx?id=40855")
    exit
}

if ($Collect)
{ CollectMaLogs $MyInvocation.MyCommand.Path }

$pathForLogsSpecified = $false
$usingLocalPath = $false
$exchangeVersion = $false
if ( -not ($pathForLogs)) {
    try {
        $exchangeVersion = (get-exchangeServer -identity $env:COMPUTERNAME).AdminDisplayVersion.ToString()
    } catch [System.Management.Automation.CommandNotFoundException] {
        $pathForLogs = (Split-Path -Parent $MyInvocation.MyCommand.Path) + '\'
        if ((Get-ChildItem | Where-Object { ($_.PSIsContainer) -and ( "Exchange_Server_Data", "Windows_Event_Logs" -contains $_.Name) } | Measure-Object).Count -eq 2) {
            try {
                Write-Host -ForegroundColor Yellow "Log structure appears to come from ExchangeLogCollector"
                $maAnalysisPath = $pathForLogs + "ManagedAvailabilityTroubleshooterAnalysis\"
                if (!(Test-Path $maAnalysisPath)) {
                    New-Item -ItemType Directory -Force -Path $maAnalysisPath | Out-Null
                    Write-Progress "Unzip logs from ExchangeLogCollector to ManagedAvailabilityTroubleshooterAnalysis folder"
                    Add-Type -AssemblyName System.IO.Compression.FileSystem
                    [System.IO.Compression.ZipFile]::ExtractToDirectory($pathForLogs + "Windows_Event_Logs\Microsoft-Exchange-ManagedAvailability.zip", $maAnalysisPath)
                    [System.IO.Compression.ZipFile]::ExtractToDirectory($pathForLogs + "Windows_Event_Logs\Microsoft-Exchange-ActiveMonitoring.zip", $maAnalysisPath)
                    [System.IO.Compression.ZipFile]::ExtractToDirectory($pathForLogs + "Windows_Event_Logs\Windows-Logs.zip", $maAnalysisPath)
                    [System.IO.Compression.ZipFile]::ExtractToDirectory($pathForLogs + "ManagedAvailabilityMonitoringLogs.zip", $maAnalysisPath)
                    $exCollectorServerLog = Get-ChildItem -Path ($pathForLogs + "Exchange_Server_Data") | Where-Object { $_.Name -like "*_ExchangeServer.txt" }
                    Copy-Item $exCollectorServerLog.FullName ($maAnalysisPath + ($exCollectorServerLog.name -replace "_ExchangeServer.txt", "_ExchangeServer_FL.TXT"))
                    $exCollectorServerHealthLog = Get-ChildItem -Path ($pathForLogs + "Exchange_Server_Data") | Where-Object { $_.Name -like "*ServerHealth.txt" }
                    Copy-Item $exCollectorServerHealthLog.FullName ($maAnalysisPath + ($exCollectorServerHealthLog.name -replace "_ServerHealth.txt", "_ServerHealth_FL.TXT"))
                    foreach ($fileInMaPath in Get-ChildItem -Path $maAnalysisPath | Where-Object { $_.PSIsContainer -eq $false }) {
                        $newFileWithOutDashInActiveM = $fileInMaPath.FullName.Replace("ActiveMonitoring-", "ActiveMonitoring")
                        $newFileWithOutDashInMA = $newFileWithOutDashInActiveM.Replace("ManagedAvailability-", "ManagedAvailability")
                        Rename-Item $fileInMaPath.FullName $newFileWithOutDashInMA
                    }

                    Write-Progress "Unzip logs from ExchangeLogCollector to ManagedAvailabilityTroubleshooterAnalysis folder"  -Completed
                }
                $pathForLogs = $maAnalysisPath
            } catch {
                Write-Host -ForegroundColor red "Encountered a failure when trying to extract logs from ExchangeLogCollector"
                Write-Host -ForegroundColor red ($error[0] | Format-List -Force | Out-String)
                exit
            }
        }
        $usingLocalPath = $true
    } catch {
        Write-Host -ForegroundColor red ($error[0] | Format-List -Force | Out-String)
        exit
    }

    if ($exchangeVersion) {
        $ProbeDefinitionEventCmd = "Get-WinEvent –ComputerName $env:COMPUTERNAME -LogName Microsoft-Exchange-ActiveMonitoring/ProbeDefinition "
        $ProbeResultEventCmd = "Get-WinEvent –ComputerName $env:COMPUTERNAME -LogName Microsoft-Exchange-ActiveMonitoring/ProbeResult "
        $MonitorDefinitionCmd = "Get-WinEvent –ComputerName $env:COMPUTERNAME -LogName Microsoft-Exchange-ActiveMonitoring/MonitorDefinition "
        $ResponderDefinitionCmd = "Get-WinEvent –ComputerName $env:COMPUTERNAME -LogName Microsoft-Exchange-ActiveMonitoring/ResponderDefinition "
        $MaintenanceDefinitionCmd = "Get-WinEvent –ComputerName $env:COMPUTERNAME -LogName Microsoft-Exchange-ActiveMonitoring/MaintenanceDefinition "
        $MaintenanceResultCmd = "Get-WinEvent –ComputerName $env:COMPUTERNAME -LogName Microsoft-Exchange-ActiveMonitoring/MaintenanceResult "
        $SystemCmd = "Get-WinEvent –ComputerName $env:COMPUTERNAME -LogName System "
        $Script:LoggingMonitoringPath = $env:exchangeInstallPath + "\Logging\Monitoring"

        if ((((Get-ExchangeServer | Where-Object { $_.AdminDisplayVersion.Major -gt 14 }).Count -lt 20) -or $AllServers) -and ($OnlyThisServer -eq $false)) {
            $ServerList = $ServerTestList = Get-ExchangeServer | Where-Object { $_.AdminDisplayVersion.Major -gt 14 }
            foreach ($exServer in $ServerTestList) {
                try {
                    Get-WinEvent -ComputerName $exServer -LogName Microsoft-Exchange-ManagedAvailability/RecoveryActionResults -MaxEvents 1 >$null
                } catch {
                    $ServerList = $ServerList | Where-Object { $_.name -ne $exServer.name }
                    Write-Host "Analyze will skip server $exServer as requests to get server events are failing ( maybe the machine is stopped or is an Edge behind a firewall ) "
                }
            }
            $RecoveryActionResultsCmd = '$ServerList | Foreach-Object { $exServer = $_ ; $RAindex = $RecoveryActions.Count;$RecoveryActions+=( Get-WinEvent -ComputerName $exServer -LogName Microsoft-Exchange-ManagedAvailability/RecoveryActionResults '
            $ServerHealthCmd = '$ServerList | Get-ServerHealth'
            $ManagedAvailabilityMonitoringCmd = '$ServerList | Foreach-Object { $alertEvents+= Get-WinEvent -ComputerName $_ -LogName Microsoft-Exchange-ManagedAvailability/Monitoring '
        } else {
            $RecoveryActionResultsCmd = "( Get-WinEvent –ComputerName $env:COMPUTERNAME -LogName Microsoft-Exchange-ManagedAvailability/RecoveryActionResults "
            $ServerHealthCmd = "Get-ServerHealth -Identity $env:COMPUTERNAME"
            $ManagedAvailabilityMonitoringCmd = "Get-WinEvent –ComputerName $env:COMPUTERNAME -LogName Microsoft-Exchange-ManagedAvailability/Monitoring "
        }
    }
}
if ($pathForLogs) {
    if ( Test-Path $pathForLogs) {
        $pathForLogsSpecified = $true
        $foundNoLogToAnalyze = $true
        if (-not $pathForLogs.EndsWith('\')) { $pathForLogs += '\' }
        $Script:LoggingMonitoringPath = $pathForLogs
        $Dir = Get-ChildItem ($pathForLogs + "*.evtx")
        $RecoveryActionResultsLog = ($Dir | Where-Object { $_.Name -like "*RecoveryActionResults.evtx" })
        if ( $RecoveryActionResultsLog.Count -ne 1) {
            if ($RecoveryActionResultsLog.Count -eq 0) {
                $errorMsg = "Can't find RecoveryActionResults evtx file in " + $pathForLogs + " directory. Check the directory"
                if ($usingLocalPath) {
                    Write-Host -ForegroundColor yellow "Exchange Powershell not loaded.`nIn case you like to analyze directly on the Exchange server , run this script in Exchange Powershell"
                    Write-Host ("No path for logs specified , using local path " + $pathForLogs)
                }
            } else {
                $errorMsg = "Too much RecoveryActionResults evtx files in " + $pathForLogs + " directory."
                foreach ($RecoveryActionResultsLogFile in $RecoveryActionResultsLog)
                { $errorMsg += "`n" + $RecoveryActionResultsLogFile.FullName }
            }
            Write-Host -ForegroundColor red ($errorMsg)
            $RecoveryActionResultsCmd = "File missing for this action.`n" + $errorMsg
        } else {
            Write-Host ("Found file " + $RecoveryActionResultsLog.FullName)
            $RecoveryActionResultsCmd = "( Get-WinEvent -path ""$RecoveryActionResultsLog"""
            $foundNoLogToAnalyze = $false
        }
        $ResponderDefinitionLog = ($Dir | Where-Object { $_.Name -like "*ResponderDefinition.evtx" })
        if ( $ResponderDefinitionLog.Count -ne 1) {
            if ($ResponderDefinitionLog.Count -eq 0)
            { $errorMsg = "Can't find ResponderDefinition evtx file in " + $pathForLogs + " directory. Check the directory"; }
            else {
                $errorMsg = "Too much ResponderDefinition evtx files in " + $pathForLogs + " directory."
                foreach ($ResponderDefinitionLogFile in $ResponderDefinitionLog)
                { $errorMsg += "`n" + $ResponderDefinitionLogFile.FullName }
            }
            Write-Host -ForegroundColor red ($errorMsg)
            $ResponderDefinitionCmd = "File missing for this action.`n" + $errorMsg
        } else {
            Write-Host ("Found file " + $ResponderDefinitionLog.FullName)
            $ResponderDefinitionCmd = "Get-WinEvent -path ""$ResponderDefinitionLog"""
            $foundNoLogToAnalyze = $false
        }
        $MaintenanceDefinitionLog = ($Dir | Where-Object { $_.Name -like "*MaintenanceDefinition.evtx" })
        if ( $MaintenanceDefinitionLog.Count -ne 1) {
            if ($MaintenanceDefinitionLog.Count -eq 0)
            { $errorMsg = "Can't find MaintenanceDefinition evtx file in " + $pathForLogs + " directory. Check the directory"; }
            else {
                $errorMsg = "Too much MaintenanceDefinition evtx files in " + $pathForLogs + " directory."
                foreach ($MaintenanceDefinitionLogFile in $MaintenanceDefinitionLog)
                { $errorMsg += "`n" + $MaintenanceDefinitionLogFile.FullName }
            }
            Write-Host -ForegroundColor red ($errorMsg)
            $MaintenanceDefinitionCmd = "File missing for this action.`n" + $errorMsg
        } else {
            Write-Host ("Found file " + $MaintenanceDefinitionLog.FullName)
            $MaintenanceDefinitionCmd = "Get-WinEvent -path ""$MaintenanceDefinitionLog"""
            $foundNoLogToAnalyze = $false
        }
        $MaintenanceResultLog = ($Dir | Where-Object { $_.Name -like "*MaintenanceResult.evtx" })
        if ( $MaintenanceResultLog.Count -ne 1) {
            if ($MaintenanceResultLog.Count -eq 0)
            { $errorMsg = "Can't find MaintenanceResult evtx file in " + $pathForLogs + " directory. Check the directory"; }
            else {
                $errorMsg = "Too much MaintenanceResult evtx files in " + $pathForLogs + " directory."
                foreach ($MaintenanceResultLogFile in $MaintenanceResultLog)
                { $errorMsg += "`n" + $MaintenanceResultLogFile.FullName }
            }
            Write-Host -ForegroundColor red ($errorMsg)
            $MaintenanceResultCmd = "File missing for this action.`n" + $errorMsg
        } else {
            Write-Host ("Found file " + $MaintenanceResultLog.FullName)
            $MaintenanceResultCmd = "Get-WinEvent -path ""$MaintenanceResultLog"""
            $foundNoLogToAnalyze = $false
        }
        $MonitorDefinitionLog = ($Dir | Where-Object { $_.Name -like "*MonitorDefinition.evtx" })
        if ( $MonitorDefinitionLog.Count -ne 1) {
            if ($MonitorDefinitionLog.Count -eq 0)
            { $errorMsg = "Can't find MonitorDefinition evtx file in " + $pathForLogs + " directory. Check the directory"; }
            else {
                $errorMsg = "Too much MonitorDefinition evtx files in " + $pathForLogs + " directory."
                foreach ($MonitorDefinitionLogFile in $MonitorDefinitionLog)
                { $errorMsg += "`n" + $MonitorDefinitionLogFile.FullName }
            }
            Write-Host -ForegroundColor red ($errorMsg)
            $MonitorDefinitionCmd = "File missing for this action.`n" + $errorMsg
        } else {
            Write-Host ("Found file " + $MonitorDefinitionLog.FullName)
            $MonitorDefinitionCmd = "Get-WinEvent -path ""$MonitorDefinitionLog"""
            $foundNoLogToAnalyze = $false
        }
        $ProbeDefinitionLog = ($Dir | Where-Object { $_.Name -like "*ProbeDefinition.evtx" })
        if ( $ProbeDefinitionLog.Count -ne 1) {
            if ($ProbeDefinitionLog.Count -eq 0)
            { $errorMsg = "Can't find ProbeDefinition evtx file in " + $pathForLogs + " directory. Check the directory"; }
            else {
                $errorMsg = "Too much ProbeDefinition evtx files in " + $pathForLogs + " directory."
                foreach ($ProbeDefinitionLogFile in $ProbeDefinitionLog)
                { $errorMsg += "`n" + $ProbeDefinitionLogFile.FullName }
            }
            Write-Host -ForegroundColor red ($errorMsg)
            $ProbeDefinitionEventCmd = "File missing for this action.`n" + $errorMsg
        } else {
            Write-Host ("Found file " + $ProbeDefinitionLog.FullName)
            $ProbeDefinitionEventCmd = "Get-WinEvent -path ""$ProbeDefinitionLog"""
            $foundNoLogToAnalyze = $false
        }
        $ProbeResultLog = ($Dir | Where-Object { $_.Name -like "*ProbeResult.evtx" })
        if ( $ProbeResultLog.Count -ne 1) {
            if ($ProbeResultLog.Count -eq 0)
            { $errorMsg = "Can't find ProbeResult evtx file in " + $pathForLogs + " directory. Check the directory"; }
            else {
                $errorMsg = "Too much ProbeResult evtx files in " + $pathForLogs + " directory."
                foreach ($ProbeResultLogFile in $ProbeResultLog)
                { $errorMsg += "`n" + $ProbeResultLogFile.FullName }
            }
            Write-Host -ForegroundColor red ($errorMsg)
            $ProbeResultEventCmd = "File missing for this action.`n" + $errorMsg
        } else {
            Write-Host ("Found file " + $ProbeResultLog.FullName)
            $ProbeResultEventCmd = "Get-WinEvent -path ""$ProbeResultLog"""
            $foundNoLogToAnalyze = $false
        }
        $ManagedAvailabilityMonitoringLog = ($Dir | Where-Object { $_.Name -like "*Exchange-ManagedAvailabilityMonitoring.evtx" })
        if ( $ManagedAvailabilityMonitoringLog.Count -ne 1) {
            if ($ManagedAvailabilityMonitoringLog.Count -eq 0)
            { $errorMsg = "Can't find ManagedAvailability Monitoring evtx file in " + $pathForLogs + " directory. Check the directory"; }
            else {
                $errorMsg = "Too much ManagedAvailability Monitoring evtx files in " + $pathForLogs + " directory."
                foreach ($ManagedAvailabilityMonitoringLogFile in $ManagedAvailabilityMonitoringLog)
                { $errorMsg += "`n" + $ManagedAvailabilityMonitoringLogFile.FullName }
            }
            Write-Host -ForegroundColor red ($errorMsg)
            $ManagedAvailabilityMonitoringCmd = "File missing for this action.`n" + $errorMsg
        } else {
            Write-Host ("Found file " + $ManagedAvailabilityMonitoringLog.FullName)
            $ManagedAvailabilityMonitoringCmd = "Get-WinEvent -path ""$ManagedAvailabilityMonitoringLog"""
            $foundNoLogToAnalyze = $false
        }
        $SystemLog = ($Dir | Where-Object { $_.Name -like "*System.evtx" })
        if ( $SystemLog.Count -ne 1) {
            if ($SystemLog.Count -eq 0)
            { $errorMsg = "Can't find System evtx file in " + $pathForLogs + " directory. Check the directory"; }
            else {
                $errorMsg = "Too much System evtx files in " + $pathForLogs + " directory."
                foreach ($SystemLogFile in $SystemLog)
                { $errorMsg += "`n" + $SystemLogFile.FullName }
            }
            Write-Host -ForegroundColor red ($errorMsg)
            $SystemCmd = "File missing for this action.`n" + $errorMsg
        } else {
            Write-Host ("Found file " + $SystemLog.FullName)
            $SystemCmd = "Get-WinEvent -path ""$SystemLog"""
            $foundNoLogToAnalyze = $false
        }
        $ServerHealthFile = Get-ChildItem ($pathForLogs + "*ServerHealth_FL.TXT")
        if ( $ServerHealthFile.Count -ne 1) {
            if ($ServerHealthFile.Count -eq 0)
            { $errorMsg = "Can't find ServerHealth_FL TXT file in " + $pathForLogs + " directory. Check the directory"; }
            else {
                $errorMsg = "Too much ServerHealth_FL TXT files in " + $pathForLogs + " directory."
                foreach ($ServerHealthFileInstance in $ServerHealthFile)
                { $errorMsg += "`n" + $ServerHealthFileInstance.FullName }
            }
            Write-Host -ForegroundColor red ($errorMsg)
            $ServerHealthFile = "File missing for this action.`n" + $errorMsg
        } else {
            Write-Host ("Found file " + $ServerHealthFile)
            $foundNoLogToAnalyze = $false
        }
        $GetExchangeServerFile = Get-ChildItem ($pathForLogs + "*_ExchangeServer_FL.TXT")
        if ( $GetExchangeServerFile.Count -ne 1) {
            if ($GetExchangeServerFile.Count -eq 0)
            { $errorMsg = "Can't find ExchangeServer_FL TXT file in " + $pathForLogs + " directory. Check the directory"; }
            else {
                $errorMsg = "Too much ExchangeServer_FL TXT files in " + $pathForLogs + " directory."
                foreach ($GetExchangeServerFileInstance in $GetExchangeServerFile)
                { $errorMsg += "`n" + $GetExchangeServerFileInstance.FullName }
            }
            Write-Host -ForegroundColor red ($errorMsg)
            $GetExchangeServerFile = "File missing for this action.`n" + $errorMsg
        } else {
            Write-Host ("Found file " + $GetExchangeServerFile)
            if ( -not (Test-Path $GetExchangeServerFile))
            { Write-Host -ForegroundColor red ("Path to ServerHealth file is invalid : $GetExchangeServerFile") }
            else {
                foreach ($line in (Get-Content $GetExchangeServerFile)) {
                    $propName = $line.split(" ")[0]
                    if ( -not $propName) { continue; }
                    if ($propName -eq "AdminDisplayVersion") {
                        $exchangeVersion = $line.split(":")[1]
                        break
                    }
                }
            }
        }
        if ($foundNoLogToAnalyze) {
            Write-Host -ForegroundColor red ("`nFound no log to analyze in " + $pathForLogs + " directory. Check the directory")
            exit
        }
    } else {
        if ( -not (($pathForLogs -eq "/?") -or ($pathForLogs -eq "/help"))) { Write-Host -ForegroundColor red "`nThe path provided as argument is not valid." }
        Write-Host $ScriptUsage
        exit
    }
}

if ($exchangeVersion) {
    $tmpBuildString = $exchangeVersion
    $tmpBuildString = $tmpBuildString.Replace(" ", "")
    $tmpBuildString = $tmpBuildString.Replace("Version", "")
    $tmpBuildString = $tmpBuildString.Replace(")", "")
    $tmpBuildString = $tmpBuildString.Replace("(Build", ".")
    $parsedExchangeVersion = $tmpBuildString.split(".")
    if ($parsedExchangeVersion.count -ne 4) {
        Write-Host -ForegroundColor red "`nError while parsing build version : $exchangeVersion .`nWill ignore build information"
        $exchangeVersion = $null
    } else {
        $exchangeVersion = $parsedExchangeVersion
        $MajorExchangeVersion = [int] $exchangeVersion[0]
        if ($MajorExchangeVersion -lt 15)
        { Write-Host -ForegroundColor red "`nThe Exchange version detected appears to be previous Exchange 2013 : $exchangeVersion.`nManaged Availability (which this tool is helping to troubleshoot) is introduced in Exchange 2013 and upper."; exit }
        $MinorExchangeVersion = [int] $exchangeVersion[1]
        $BuildExchangeVersion = [int] $exchangeVersion[2]
        #		$RevisionExchangeVersion = [int] $exchangeVersion[3]
    }
}

$ForceRebootChoice = New-Object System.Management.Automation.Host.ChoiceDescription "My Exchange server is rebooting / encountered a blueScreen (&ForceReboot)", "My Exchange server is rebooting /encounter a blueScreen"
$AllRecoveryActionsChoice = New-Object System.Management.Automation.Host.ChoiceDescription "Some Exchange services are restarting , or some components are inactive (&All Recovery Actions)", "Some Exchange services are restarting , or some components are inactive"
$CheckSpecificResponderOrMonitorOrProbe = New-Object System.Management.Automation.Host.ChoiceDescription "I need to check a specific Responder/Monitor or Probe - can be reported by SCOM (&Specific Responder/Monitor/Probe)", "I need to check a specific Responder/Monitor or Probe - can be reported by SCOM"
$UnhealthyMonitorChoice = New-Object System.Management.Automation.Host.ChoiceDescription "Some Monitors appears as Unhealthy - this can be reported by a SCOM alert ( &Unhealthy Monitors)", "Some Monitors appears as Unhealthy - this can be reported by a SCOM alert"
$ProbeErrorsChoice = New-Object System.Management.Automation.Host.ChoiceDescription "Check last Probe Errors in order to find which probe is failing at the time of my problem (&Probe errors)", "I like to check last Probe Errors in order to find which probe is failing at the time of my problem"
$SCOMAlertsChoice = New-Object System.Management.Automation.Host.ChoiceDescription "Display SCOM Alerts (&Display SCOM Alerts)", "Display SCOM Alerts"
$CollectMALogsChoice = New-Object System.Management.Automation.Host.ChoiceDescription "Collect Managed Availability logs (&Collect Managed Availability logs)", "Collect Managed Availability logs"
$InvestigationChoose = 0
if ($exchangeVersion) {
    $InvestigationChoose = $host.ui.PromptForChoice("", "`nSelect the Option that best describes the issue that you are facing:", [System.Management.Automation.Host.ChoiceDescription[]]($ForceRebootChoice, $AllRecoveryActionsChoice, $CheckSpecificResponderOrMonitorOrProbe, $SCOMAlertsChoice, $UnhealthyMonitorChoice, $ProbeErrorsChoice, $CollectMALogsChoice), 0)
} else {
    $InvestigationChoose = $host.ui.PromptForChoice("", "`nSelect the Option that best describes the issue that you are facing:", [System.Management.Automation.Host.ChoiceDescription[]]($ForceRebootChoice, $AllRecoveryActionsChoice, $CheckSpecificResponderOrMonitorOrProbe, $SCOMAlertsChoice, $UnhealthyMonitorChoice, $ProbeErrorsChoice), 0)
}

if ($InvestigationChoose -eq 0 -or $InvestigationChoose -eq 1) {

    if ($pathForLogsSpecified)
    {	$HighAvailabilityPath = $pathForLogs + "HighAvailability\"	}
    else
    {	$HighAvailabilityPath = $env:exchangeInstallPath + "\Logging\HighAvailability\"	}

    if (Test-Path $HighAvailabilityPath ) {
        foreach ($HighAvailabilityFile in Get-ChildItem ($HighAvailabilityPath + "*PersistedBugCheckInfo*.dat")) {
            Write-Host -ForegroundColor yellow "`n`nPersistedBugCheckInfo file found : This persistent crash info point there was a force reboot triggered by Exchange"
            Write-Host "This is likely running outside of Managed Availability but by this crash is triggered by Exchange to force a failover"
            Write-Host "`nHere are the info regarding this force reboot : `n"
            $HighAvailabilityFile = Get-Content $HighAvailabilityFile -Encoding Unknown
            Write-Host $HighAvailabilityFile
            Write-Host "`n"
            foreach ($line in $HighAvailabilityFile) {
                if ($line -like "*GetDiskFreeSpaceEx*") {
                    Write-Host -ForegroundColor yellow "Exchange triggered this force reboot as Exchange get no reply from GetDiskFreeSpaceEx call to check disk space for a long time"
                    Write-Host -ForegroundColor yellow "This can be due to Cache manager throttling the request as there is too much slow disk write"
                    Write-Host -ForegroundColor yellow "Involve your disk experts to check if you get slow disk access at that time"

                    Write-Host -foreground yellow ("`n`nKnown issue found !!")
                }
            }
            Write-Host -ForegroundColor yellow  "Please check the issue detected upper. To continue, press any key"
            $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
    }

    $CheckRecoveryActionForMultipleMachines = $RecoveryActionResultsCmd -like "*Foreach-Object*"
    $RecoveryActions = $null
    if ($CheckRecoveryActionForMultipleMachines)
    { TestFileOrCmd ($RecoveryActionResultsCmd + ")}") }
    else
    { TestFileOrCmd ($RecoveryActionResultsCmd + ")") }
    $RecoveryActionsCmd = $RecoveryActionResultsCmd + '| % {[XML]$_.toXml()}).event.userData.eventXml'
    if ($InvestigationChoose -eq 0)
    { $RecoveryActionsCmd += '| ? {$_.Id -eq "ForceReboot"}' }
    if ($CheckRecoveryActionForMultipleMachines)
    { $RecoveryActionsCmd += '; For ($i=$RAindex; $i -lt $RecoveryActions.Count; $i++) { $RecoveryActions[$i]|Add-Member -Name "MachineName" -Value $exServer -MemberType NoteProperty}};$RecoveryActions' }
    Write-Verbose $RecoveryActionsCmd
    Write-Progress "Checking Recovery Actions"
    $RecoveryActions = Invoke-Expression $RecoveryActionsCmd
    Write-Progress "Checking Recovery Actions" -Completed
    if ($RecoveryActions) {
        if ($InvestigationChoose -eq 0) {
            Write-Host ("`nLast Reboot was triggered by the Responder " + $RecoveryActions[0].RequestorName + " at " + $RecoveryActions[0].StartTime + " ." )
            $SelectTitle = "Select the ForceReboot that you like to investigate"
        } else
        { $SelectTitle = "Select the Recovery Action that you like to investigate" }
        Write-Host $SelectTitle
        Start-Sleep -s 1
        $RAOutGridViewCmd = '$RecoveryActions | select -Property '
        if ($CheckRecoveryActionForMultipleMachines)
        { $RAOutGridViewCmd += "MachineName," }
        $RAOutGridViewCmd += '@{n="StartTime (GMT)";e={$_.StartTime}}, @{n="EndTime (GMT)";e={$_.EndTime}} , Id , ResourceName , InstanceId , RequestorName , Result , State , ExceptionName,ExceptionMessage,LamProcessStartTime,ThrottleIdentity , ThrottleParametersXml , Context | Sort-Object "StartTime (GMT)" -Descending | Out-GridView -PassThru -title $SelectTitle'
        Write-Verbose $RAOutGridViewCmd
        $RecoveryActionToInvestigate = Invoke-Expression $RAOutGridViewCmd
        if ($RecoveryActionToInvestigate) {
            if ($RecoveryActionToInvestigate.Count -gt 1 )
            { $RecoveryActionToInvestigate = $RecoveryActionToInvestigate[0] }
            if ($CheckRecoveryActionForMultipleMachines) {
                if ([string]::Compare($RecoveryActionToInvestigate.MachineName, $env:COMPUTERNAME, $true) -ne 0) {
                    Write-Host -ForegroundColor yellow ("`nThe RecoveryAction you select is regarding a different server : " + $RecoveryActionToInvestigate.MachineName + " .")
                    Write-Host -ForegroundColor yellow ("Run this script on this server directly to analyze this RecoveryAction further." )
                    exit
                }
            }
            InvestigateResponder $RecoveryActionToInvestigate.RequestorName $RecoveryActionToInvestigate.ResourceName
        } else
        { if ($InvestigationChoose -eq 0) { Write-Host ("`nYou have not selected any occurrence. Run the script again and select an occurrence" ) } }
    } else
    { Write-Host "`nFound no event with ID ForceReboot in RecoveryActionResults log. Health Manager shouldn't have triggered a reboot recently." }
}

if ($InvestigationChoose -eq 2) {
    $SpecificResponderOrMonitorOrProbe = Read-Host ("Enter the name of the Responder/Monitor or Probe ")
    if ($SpecificResponderOrMonitorOrProbe) {
        $IsItAResponderOrMonitorOrProbe = 0
        if ($SpecificResponderOrMonitorOrProbe.split("/")[0].ToLower().EndsWith("probe")) {
            $IsItAResponderOrMonitorOrProbe = 2
        } elseif ($SpecificResponderOrMonitorOrProbe.split("/")[0].ToLower().EndsWith("monitor")) {
            $IsItAResponderOrMonitorOrProbe = 1
        } else {
            $IsResponder = New-Object System.Management.Automation.Host.ChoiceDescription "&Responder", "Responder"
            $IsMonitor = New-Object System.Management.Automation.Host.ChoiceDescription "&Monitor", "Monitor"
            $IsProbe = New-Object System.Management.Automation.Host.ChoiceDescription "&Probe", "Probe"
            $IsItAResponderOrMonitorOrProbe = $host.ui.PromptForChoice("", "Is it a : ", [System.Management.Automation.Host.ChoiceDescription[]]($IsResponder, $IsMonitor, $IsProbe), 0)
        }
        switch ( $IsItAResponderOrMonitorOrProbe) {
            0 { InvestigateResponder $SpecificResponderOrMonitorOrProbe $null }
            1 {
                InvestigateMonitor -MonitorToInvestigate $SpecificResponderOrMonitorOrProbe `
                    -ResourceNameToInvestigate $null `
                    -ResponderTargetResource $null `
                    -ResponderToInvestigate $null
            }
            2 {
                InvestigateProbe -ProbeToInvestigate $SpecificResponderOrMonitorOrProbe `
                    -MonitorToInvestigate $null `
                    -ResponderToInvestigate $null `
                    -ResourceNameToInvestigate $null `
                    -ResponderTargetResource $null
            }
        }
    } else
    { Write-Host -ForegroundColor red ("No name specified") }
    exit
}
if ($InvestigationChoose -eq 3) {
    $CheckAlertsForMultipleMachines = $ManagedAvailabilityMonitoringCmd -like "*Foreach-Object*"
    $alertEvents = $null
    if ($CheckAlertsForMultipleMachines)
    { TestFileOrCmd ($ManagedAvailabilityMonitoringCmd + " }") }
    else
    { TestFileOrCmd $ManagedAvailabilityMonitoringCmd }
    $ManagedAvailabilityMonitoringCmd = $ManagedAvailabilityMonitoringCmd + '-MaxEvents 200 |? {$_.Id -eq 4 }'
    if ($CheckAlertsForMultipleMachines)
    { $ManagedAvailabilityMonitoringCmd += ' };$alertEvents' }
    Write-Verbose $ManagedAvailabilityMonitoringCmd
    Write-Progress "Checking SCOM Alerts"
    $alertEvents = Invoke-Expression $ManagedAvailabilityMonitoringCmd
    $alertEventsProps = ($alertEvents | ForEach-Object { [XML]$_.toXml() }).event.userData.eventXml
    for ($i = 0; $i -lt $alertEventsProps.Count; $i++) {
        $alertEventsProps[$i] | Add-Member TimeCreated $alertEvents[$i].TimeCreated
        if ($CheckAlertsForMultipleMachines)
        { $alertEventsProps[$i] | Add-Member MachineName $alertEvents[$i].MachineName }
    }
    Write-Progress "Checking SCOM Alerts" -Completed
    $alertOutGridViewCmd = '$alertEventsProps | select -Property '
    if ($CheckAlertsForMultipleMachines)
    { $alertOutGridViewCmd += "MachineName," }
    $alertOutGridViewCmd += 'TimeCreated, Monitor,HealthSet,Subject,Message | Out-GridView -title "SCOM Alerts"'
    Invoke-Expression $alertOutGridViewCmd
}
if ($InvestigationChoose -eq 4) {
    InvestigateUnhealthyMonitor $ServerHealthFile
}
if ($InvestigationChoose -eq 5) {
    ParseProbeResult -FilterXpath "*[UserData[EventXML [ResultType='4']]]" `
        -MonitorToInvestigate $null `
        -ResponderToInvestigate $null
}
if (($InvestigationChoose -eq 6) -and ($exchangeVersion)) {
    CollectMaLogs $MyInvocation.MyCommand.Path
}
