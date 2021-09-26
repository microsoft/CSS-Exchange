# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-ActionPlan.ps1
. $PSScriptRoot\..\New-ErrorContext.ps1
Function Test-InitializePermissionsOfDomain {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $ErrorRefAndSetupLog
    )
    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $errorReference = $ErrorRefAndSetupLog.ErrorReference
        $setupLogReviewer = $ErrorRefAndSetupLog.SetupLogReviewer

        #_27a706ffe123425f9ee60cb02b930e81 initialize permissions of the domain.
        if ($errorReference.Matches.Groups[1].Value -eq "DomainGlobalConfig___27a706ffe123425f9ee60cb02b930e81") {

            Write-Verbose "KnownOrganizationPreparationErrors - found DomainGlobalConfig___27a706ffe123425f9ee60cb02b930e81"
            $errorContext = $setupLogReviewer | GetFirstErrorWithContextToLine $errorReference.LineNumber 1
            $permissionsError = $errorContext | Select-String "SecErr: DSID-.+ problem 4003 \(INSUFF_ACCESS_RIGHTS\)"

            if ($null -ne $permissionsError) {
                Write-Verbose "KnownOrganizationPreparationErrors - Found INSUFF_ACCESS_RIGHTS"
                $objectDN = $errorContext[0] | Select-String "Used domain controller (.+) to read object (.+)."

                if ($null -ne $objectDN) {
                    Write-Verbose "KnownOrganizationPreparationErrors - used domain controller and to read object"
                    $errorContext | Select-Object -First 10 | New-ErrorContext
                    New-ActionPlan @(
                        "We failed to have the correct permissions to write ACE to '$($objectDN.Matches.Groups[2].Value)' as the current user $($setupLogReviewer.User)",
                        "- Make sure there are no denies for this user on the object",
                        "- By default Enterprise Admins and BUILTIN\Administrators give you the rights to do this action (dsacls 'write permissions')",
                        "- If unable to determine the cause, you can apply FULL CONTROL to '$($objectDN.Matches.Groups[2].Value)' for the user $($setupLogReviewer.User)"
                    )
                    return
                }
            }
            Write-Verbose "Failed to find permissions error"
        }
    }
}
