Function Test-KnownOrganizationPreparationErrors {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $SetupLogReviewer
    )
    process {
        $errorReference = $SetupLogReviewer.SelectStringLastRunOfExchangeSetup("\[ERROR-REFERENCE\] Id=(.+) Component=")
        if ($null -eq $errorReference) {
            return $false
        }

        $errorLine = $SetupLogReviewer.SelectStringLastRunOfExchangeSetup("\[ERROR\] The well-known object entry (.+) on the otherWellKnownObjects attribute in the container object (.+) points to an invalid DN or a deleted object")

        if ($null -ne $errorLine) {

            $SetupLogReviewer.WriteErrorContext($errorLine.Line)
            [string]$ap = "Option 1: Restore the objects that were deleted."
            [string]$ap += "`r`n`tOption 2: Run the SetupAssist.ps1 script with '-OtherWellKnownObjects' to be able address deleted objects type"
            $SetupLogReviewer.WriteActionPlan($ap)
            return $true
        }

        #_27a706ffe123425f9ee60cb02b930e81 initialize permissions of the domain.
        if ($errorReference.Matches.Groups[1].Value -eq "DomainGlobalConfig___27a706ffe123425f9ee60cb02b930e81") {

            $errorContext = $SetupLogReviewer.FirstErrorWithContextToLine($errorReference.LineNumber, 1)
            $permissionsError = $errorContext | Select-String "SecErr: DSID-03152857, problem 4003 \(INSUFF_ACCESS_RIGHTS\)"
            if ($null -ne $permissionsError) {
                $objectDN = $errorContext[0] | Select-String "Used domain controller (.+) to read object (.+)."

                if ($null -ne $objectDN) {
                    $SetupLogReviewer.WriteErrorContext(($errorContext | Select-Object -First 10))
                    [string]$ap = "We failed to have the correct permissions to write ACE to '$($objectDN.Matches.Groups[2].Value)' as the current user $($SetupLogReviewer.User)"
                    [string]$ap += "`r`n`t- Make sure there are no denies for this user on the object"
                    [string]$ap += "`r`n`t- By default Enterprise Admins and BUILTIN\Administrators give you the rights to do this action (dsacls 'write permissions')"
                    [string]$ap += "`r`n`t- If unable to determine the cause, you can apply FULL CONTROL to '$($objectDN.Matches.Groups[2].Value)' for the user $($SetupLogReviewer.User)"
                    $SetupLogReviewer.WriteActionPlan($ap)
                    return $true
                }
            }
        }

        $invalidWKObjectTargetException = $SetupLogReviewer.SelectStringLastRunOfExchangeSetup("The well-known object entry with the GUID `"(.+)`", which is on the `"(.+)`" container object's otherWellKnownObjects attribute, refers to a group `"(.+)`" of the wrong group type. Either delete the well-known object entry, or promote the target object to `"(.+)`".")

        if ($null -ne $invalidWKObjectTargetException) {
            $SetupLogReviewer.WriteErrorContext($invalidWKObjectTargetException.Line)
            $ap = "- Change the {0} object to {1}" -f $invalidWKObjectTargetException.Matches.Groups[3].Value,
            $invalidWKObjectTargetException.Matches.Groups[4].Value
            $ap += "`r`n`t- Another problem can be that the group is set correctly, but is mail enabled and shouldn't be."
            $SetupLogReviewer.WriteActionPlan($ap)
            return $true
        }

        $errorContext = $SetupLogReviewer.FirstErrorWithContextToLine($errorReference.LineNumber)

        $msExchangeSecurityGroupsContainerDeleted = $errorContext | Select-String -Pattern "System.NullReferenceException: Object reference not set to an instance of an object.", `
            "Microsoft.Exchange.Management.Tasks.InitializeExchangeUniversalGroups.CreateOrMoveEWPGroup\(ADGroup ewp, ADOrganizationalUnit usgContainer\)"

        if ($null -ne $msExchangeSecurityGroupsContainerDeleted) {

            if ($msExchangeSecurityGroupsContainerDeleted[0].Pattern -ne $msExchangeSecurityGroupsContainerDeleted[1].Pattern -and
                $msExchangeSecurityGroupsContainerDeleted[0].LineNumber -eq ($msExchangeSecurityGroupsContainerDeleted[1].LineNumber - 1)) {
                $SetupLogReviewer.WriteErrorContext(@($msExchangeSecurityGroupsContainerDeleted[0].Line,
                        $msExchangeSecurityGroupsContainerDeleted[1].Line))

                $SetupLogReviewer.WriteActionPlan("'OU=Microsoft Exchange Security Groups' was deleted from the root of the domain. We need to have it created again at the root of the domain to continue.")
                return $true
            }
        }

        $exceptionADOperationFailedAlreadyExist = $errorContext | Select-String `
            -Pattern "Active Directory operation failed on (.+). The object '(.+)' already exists." `
        | Select-Object -First 1

        if ($null -ne $exceptionADOperationFailedAlreadyExist) {
            $SetupLogReviewer.WriteErrorContext($exceptionADOperationFailedAlreadyExist.Line)
            $SetupLogReviewer.WriteActionPlan("Validate permissions are inherited to object `"$($exceptionADOperationFailedAlreadyExist.Matches.Groups[2])`" and that there aren't any denies that shouldn't be there")
            return $true
        }
    }
}