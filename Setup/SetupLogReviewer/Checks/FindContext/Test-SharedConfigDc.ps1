# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-ActionPlan.ps1
. $PSScriptRoot\..\New-ErrorContext.ps1
function Test-SharedConfigDc {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $SetupLogReviewer
    )
    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $sharedConfigDc = $SetupLogReviewer | SelectStringLastRunOfExchangeSetup "\[ERROR\] Unable to set shared config DC"
        $errorCausedFailure = $SetupLogReviewer | SelectStringLastRunOfExchangeSetup "\[ERROR-REFERENCE\] Id=AllADRolesCommonServiceControl___ee47ab1c06fb47919398e2e95ed99c6c"
        $serviceStartedLine = "It appears that the Microsoft Exchange Active Directory Topology service was started on the server and we ran into a different inner exception."
        $noteCommon = "NOTE: It is common that the service will not stay started after the initial failure, make sure you keep the Microsoft Exchange Active Directory Topology service running during the entire setup process"
        $genericActionPlan = @("Carefully read the inner exception and review the application logs to determine why we can't connect to Active Directory.",
            [System.Environment]::NewLine,
            "       $noteCommon")

        if ($null -ne $sharedConfigDc -and
            $null -ne $errorCausedFailure) {
            # Now that we have this particular error, what matters is the inner exception.
            # cSpell:disable
            $innerError = $SetupLogReviewer | SelectStringLastRunOfExchangeSetup "\] An error ocurred while setting shared config DC\. Error: (.+)"
            $innerExceptionCatch = $SetupLogReviewer | SelectStringLastRunOfExchangeSetup "\] An exception ocurred while setting shared config DC\. Exception: (.+)"
            # cSpell:enable

            if ($null -ne $innerError) {
                $innerErrorValue = $innerError.Matches.Groups[1].Value
                $sharedConfigDc.Line + [System.Environment]::NewLine + "Inner Exception: $innerErrorValue" | New-ErrorContext

                # cSpell:disable
                # coudn't spelled incorrectly in code.
                $serviceStopString = "Topology Provider coundn't find the Microsoft Exchange Active Directory Topology service on end point 'TopologyClientTcpEndpoint (localhost)'."
                # cSpell:enable
                if ($innerErrorValue -eq $serviceStopString) {
                    New-ActionPlan @(
                        "1. The service needs to be started prior to setup & during setup. Setup could be stopping and disabling this service preventing setup from working.",
                        "     MAKE SURE IT IS RUNNING DURING THE WHOLE SETUP AFTER COPYING FILES",
                        "2. After starting the service, make sure it stays running and check the application logs to make sure there are no errors.",
                        "     We could have failed the first time because we couldn't find a suitable domain controller for various number of reasons.",
                        "     If those errors are still there after starting the service, you need to address those prior to trying to run setup again."
                    )
                } else {
                    New-ActionPlan @(
                        $serviceStartedLine,
                        $genericActionPlan
                    )
                }
            } elseif ($null -ne $innerExceptionCatch) {
                $innerExceptionCatchValue = $innerExceptionCatch.Matches.Groups[1].Value
                $sharedConfigDc.Line + [System.Environment]::NewLine + "Inner Exception: $innerExceptionCatchValue" | New-ErrorContext

                New-ActionPlan @(
                    $serviceStartedLine,
                    $genericActionPlan
                )
            } else {
                $sharedConfigDc.Line | New-ErrorContext
                New-ActionPlan @(
                    "Determined that we found an issue with trying to set the Shared Config DC, but was unable to get find the inner exception.",
                    "Start the Microsoft Exchange Active Directory Topology service and see if there are any errors in the application log related to the service after it has started.",
                    "Troubleshoot those error messages prior to trying to run setup again.",
                    $noteCommon
                )
            }
        }
    }
}
