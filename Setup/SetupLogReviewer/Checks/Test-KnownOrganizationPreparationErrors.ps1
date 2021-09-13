# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\New-ActionPlan.ps1
. $PSScriptRoot\New-ErrorContext.ps1
. $PSScriptRoot\New-WriteObject.ps1
Function Test-KnownOrganizationPreparationErrors {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $SetupLogReviewer
    )
    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $errorReference = $SetupLogReviewer | SelectStringLastRunOfExchangeSetup "\[ERROR-REFERENCE\] Id=(.+) Component="

        if ($null -eq $errorReference) {
            Write-Verbose "KnownOrganizationPreparationErrors failed to find error reference"
            return
        }

        $errorLine = $SetupLogReviewer |
            SelectStringLastRunOfExchangeSetup "\[ERROR\] The well-known object entry (.+) on the otherWellKnownObjects attribute in the container object (.+) points to an invalid DN or a deleted object"

        if ($null -ne $errorLine) {

            $errorLine.Line | New-ErrorContext
            New-ActionPlan @(
                "Option 1: Restore the objects that were deleted.",
                "Option 2: Run the SetupAssist.ps1 script to address the deleted objects type"
            )
            return
        }

        #_27a706ffe123425f9ee60cb02b930e81 initialize permissions of the domain.
        if ($errorReference.Matches.Groups[1].Value -eq "DomainGlobalConfig___27a706ffe123425f9ee60cb02b930e81") {

            Write-Verbose "KnownOrganizationPreparationErrors - found DomainGlobalConfig___27a706ffe123425f9ee60cb02b930e81"
            $errorContext = $SetupLogReviewer | GetFirstErrorWithContextToLine $errorReference.LineNumber 1
            $permissionsError = $errorContext | Select-String "SecErr: DSID-.+ problem 4003 \(INSUFF_ACCESS_RIGHTS\)"

            if ($null -ne $permissionsError) {
                Write-Verbose "KnownOrganizationPreparationErrors - Found INSUFF_ACCESS_RIGHTS"
                $objectDN = $errorContext[0] | Select-String "Used domain controller (.+) to read object (.+)."

                if ($null -ne $objectDN) {
                    Write-Verbose "KnownOrganizationPreparationErrors - used domain controller and to read object"
                    $errorContext | Select-Object -First 10 | New-ErrorContext
                    New-ActionPlan @(
                        "We failed to have the correct permissions to write ACE to '$($objectDN.Matches.Groups[2].Value)' as the current user $($SetupLogReviewer.User)",
                        "- Make sure there are no denies for this user on the object",
                        "- By default Enterprise Admins and BUILTIN\Administrators give you the rights to do this action (dsacls 'write permissions')",
                        "- If unable to determine the cause, you can apply FULL CONTROL to '$($objectDN.Matches.Groups[2].Value)' for the user $($SetupLogReviewer.User)"
                    )
                    return
                }
            }
            Write-Verbose "Failed to find permissions error"
        }

        $invalidWKObjectTargetException = $SetupLogReviewer |
            SelectStringLastRunOfExchangeSetup "The well-known object entry with the GUID `"(.+)`", which is on the `"(.+)`" container object's otherWellKnownObjects attribute, refers to a group `"(.+)`" of the wrong group type. Either delete the well-known object entry, or promote the target object to `"(.+)`"."

        if ($null -ne $invalidWKObjectTargetException) {
            $invalidWKObjectTargetException.Line | New-ErrorContext
            New-ActionPlan @(
                "- Change the $($invalidWKObjectTargetException.Matches.Groups[3].Value) object to $($invalidWKObjectTargetException.Matches.Groups[4].Value)",
                "- Another problem can be that the group is set correctly, but is mail enabled and shouldn't be."
            )
            return
        }

        $errorContext = $SetupLogReviewer | GetFirstErrorWithContextToLine $errorReference.LineNumber
        $msExchangeSecurityGroupsContainerDeleted = $errorContext | Select-String -Pattern "System.NullReferenceException: Object reference not set to an instance of an object.", `
            "Microsoft.Exchange.Management.Tasks.InitializeExchangeUniversalGroups.CreateOrMoveEWPGroup\(ADGroup ewp, ADOrganizationalUnit usgContainer\)"

        if ($null -ne $msExchangeSecurityGroupsContainerDeleted) {
            Write-Verbose "Found matching patterns - msExchangeSecurityGroupsContainerDeleted"

            if ($msExchangeSecurityGroupsContainerDeleted[0].Pattern -ne $msExchangeSecurityGroupsContainerDeleted[1].Pattern -and
                $msExchangeSecurityGroupsContainerDeleted[0].LineNumber -eq ($msExchangeSecurityGroupsContainerDeleted[1].LineNumber - 1)) {
                $errorContext = @()
                $errorContext += $msExchangeSecurityGroupsContainerDeleted[0].Line
                $errorContext += $msExchangeSecurityGroupsContainerDeleted[1].Line
                $errorContext | New-ErrorContext
                Write-Verbose "Matched additional information"
                New-ActionPlan "'OU=Microsoft Exchange Security Groups' was deleted from the root of the domain. We need to have it created again at the root of the domain to continue."
                return
            }
            Write-Verbose "Failed to match additional patterns"
        }

        $exceptionADOperationFailedAlreadyExist = $errorContext | Select-String `
            -Pattern "Active Directory operation failed on (.+). The object '(.+)' already exists." | Select-Object -First 1

        if ($null -ne $exceptionADOperationFailedAlreadyExist) {
            $exceptionADOperationFailedAlreadyExist.Line | New-ErrorContext

            if ($exceptionADOperationFailedAlreadyExist.Matches.Groups[2].Value.StartsWith("CN=Folder Hierarchies,CN=Exchange Administrative Group")) {
                New-ActionPlan @(
                    "Public Folder Object needs to be created",
                    "- Open ADSIEDIT and go to this location'$($exceptionADOperationFailedAlreadyExist.Matches.Groups[2].Value)'",
                    "- Right Click select New - Object",
                    "- Select mxExchPFTree",
                    "- Enter any value for the cn (Common Name) value, such as PF",
                    "- Right-click the newly created msExchPFTree object and select Properties",
                    "- On the Attribute Editor tab, click msExchPFTreeType, and then click Edit.",
                    "- In the Value box type 1, and then click OK two times.",
                    "- Exit and wait for AD Replication"
                )
            } else {
                New-ActionPlan "Validate permissions are inherited to object `"$($exceptionADOperationFailedAlreadyExist.Matches.Groups[2])`" and that there aren't any denies that shouldn't be there"
            }
            return
        }
        Write-Verbose "KnownOrganizationPreparationErrors - no known issue"
    }
}
