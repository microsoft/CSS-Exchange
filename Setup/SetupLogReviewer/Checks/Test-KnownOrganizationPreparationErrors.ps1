# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Test-KnownOrganizationPreparationErrors {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $SetupLogReviewer
    )
    begin {
        $diagnosticContext = New-Object 'System.Collections.Generic.List[string]'
        $displayContext = New-Object 'System.Collections.Generic.List[PSCustomObject]'
        $foundKnownIssue = $true
        $actionPlan = New-Object 'System.Collections.Generic.List[string]'
        $errorContext = New-Object 'System.Collections.Generic.List[string]'
        $writeErrorContext = New-Object 'System.Collections.Generic.List[string]'
        $writeWarning = [string]::Empty
        $breadCrumb = 0
    }
    process {
        $diagnosticContext.Add("KnownOrganizationPreparationErrors $($breadCrumb; $breadCrumb++)")
        $errorReference = $SetupLogReviewer.SelectStringLastRunOfExchangeSetup("\[ERROR-REFERENCE\] Id=(.+) Component=")

        if ($null -eq $errorReference) {
            $foundKnownIssue = $false
            $diagnosticContext.Add("KnownOrganizationPreparationErrors failed to find error reference")
            return
        }

        $errorLine = $SetupLogReviewer.SelectStringLastRunOfExchangeSetup("\[ERROR\] The well-known object entry (.+) on the otherWellKnownObjects attribute in the container object (.+) points to an invalid DN or a deleted object")
        $diagnosticContext.Add("KnownOrganizationPreparationErrors $($breadCrumb; $breadCrumb++)")

        if ($null -ne $errorLine) {

            $writeErrorContext.Add($errorLine.Line)
            $actionPlan.Add("Option 1: Restore the objects that were deleted.")
            $actionPlan.Add("Option 2: Run the SetupAssist.ps1 script with '-OtherWellKnownObjects' to be able address deleted objects type")
            return
        }

        $diagnosticContext.Add("KnownOrganizationPreparationErrors $($breadCrumb; $breadCrumb++)")
        #_27a706ffe123425f9ee60cb02b930e81 initialize permissions of the domain.
        if ($errorReference.Matches.Groups[1].Value -eq "DomainGlobalConfig___27a706ffe123425f9ee60cb02b930e81") {

            $diagnosticContext.Add("KnownOrganizationPreparationErrors - found DomainGlobalConfig___27a706ffe123425f9ee60cb02b930e81")
            $errorContext = $SetupLogReviewer.FirstErrorWithContextToLine($errorReference.LineNumber, 1)
            $permissionsError = $errorContext | Select-String "SecErr: DSID-.+ problem 4003 \(INSUFF_ACCESS_RIGHTS\)"

            if ($null -ne $permissionsError) {
                $diagnosticContext.Add("KnownOrganizationPreparationErrors - Found INSUFF_ACCESS_RIGHTS")
                $objectDN = $errorContext[0] | Select-String "Used domain controller (.+) to read object (.+)."

                if ($null -ne $objectDN) {
                    $diagnosticContext.Add("KnownOrganizationPreparationErrors - used domain controller and to read object")
                    $errorContext | Select-Object -First 10 |
                        ForEach-Object { $writeErrorContext.Add($_) }
                    $actionPlan.Add("We failed to have the correct permissions to write ACE to '$($objectDN.Matches.Groups[2].Value)' as the current user $($SetupLogReviewer.User)")
                    $actionPlan.Add("- Make sure there are no denies for this user on the object")
                    $actionPlan.Add("- By default Enterprise Admins and BUILTIN\Administrators give you the rights to do this action (dsacls 'write permissions')")
                    $actionPlan.Add("- If unable to determine the cause, you can apply FULL CONTROL to '$($objectDN.Matches.Groups[2].Value)' for the user $($SetupLogReviewer.User)")
                    return
                }
            }
            $displayContext.Add($SetupLogReviewer.GetWriteObject("Failed to find permissions error"))
        }

        $invalidWKObjectTargetException = $SetupLogReviewer.SelectStringLastRunOfExchangeSetup("The well-known object entry with the GUID `"(.+)`", which is on the `"(.+)`" container object's otherWellKnownObjects attribute, refers to a group `"(.+)`" of the wrong group type. Either delete the well-known object entry, or promote the target object to `"(.+)`".")
        $diagnosticContext.Add("KnownOrganizationPreparationErrors $($breadCrumb; $breadCrumb++)")

        if ($null -ne $invalidWKObjectTargetException) {
            $writeErrorContext.Add($invalidWKObjectTargetException.Line)
            $actionPlan.Add("- Change the $($invalidWKObjectTargetException.Matches.Groups[3].Value) object to $($invalidWKObjectTargetException.Matches.Groups[4].Value)")
            $actionPlan.Add("- Another problem can be that the group is set correctly, but is mail enabled and shouldn't be.")
            return
        }

        $errorContext = $SetupLogReviewer.FirstErrorWithContextToLine($errorReference.LineNumber)
        $msExchangeSecurityGroupsContainerDeleted = $errorContext | Select-String -Pattern "System.NullReferenceException: Object reference not set to an instance of an object.", `
            "Microsoft.Exchange.Management.Tasks.InitializeExchangeUniversalGroups.CreateOrMoveEWPGroup\(ADGroup ewp, ADOrganizationalUnit usgContainer\)"
        $diagnosticContext.Add("KnownOrganizationPreparationErrors $($breadCrumb; $breadCrumb++)")

        if ($null -ne $msExchangeSecurityGroupsContainerDeleted) {
            $diagnosticContext.Add("Found matching patterns - msExchangeSecurityGroupsContainerDeleted")

            if ($msExchangeSecurityGroupsContainerDeleted[0].Pattern -ne $msExchangeSecurityGroupsContainerDeleted[1].Pattern -and
                $msExchangeSecurityGroupsContainerDeleted[0].LineNumber -eq ($msExchangeSecurityGroupsContainerDeleted[1].LineNumber - 1)) {
                $writeErrorContext.Add($msExchangeSecurityGroupsContainerDeleted[0].Line)
                $writeErrorContext.Add($msExchangeSecurityGroupsContainerDeleted[1].Line)
                $diagnosticContext.Add("Matched additional information")
                $actionPlan.Add("'OU=Microsoft Exchange Security Groups' was deleted from the root of the domain. We need to have it created again at the root of the domain to continue.")
                return
            }
            $diagnosticContext.Add("Failed to match additional patterns")
        }

        $diagnosticContext.Add("KnownOrganizationPreparationErrors $($breadCrumb; $breadCrumb++)")
        $exceptionADOperationFailedAlreadyExist = $errorContext | Select-String `
            -Pattern "Active Directory operation failed on (.+). The object '(.+)' already exists." | Select-Object -First 1

        if ($null -ne $exceptionADOperationFailedAlreadyExist) {
            $writeErrorContext.Add($exceptionADOperationFailedAlreadyExist.Line)

            if ($exceptionADOperationFailedAlreadyExist.Matches.Groups[2].Value.StartsWith("CN=Folder Hierarchies,CN=Exchange Administrative Group")) {
                $actionPlan.Add("Public Folder Object needs to be created")
                $actionPlan.Add("- Open ADSIEDIT and go to this location'$($exceptionADOperationFailedAlreadyExist.Matches.Groups[2].Value)'")
                $actionPlan.Add("- Right Click select New - Object")
                $actionPlan.Add("- Select mxExchPFTree")
                $actionPlan.Add("- Enter any value for the cn (Common Name) value, such as PF")
                $actionPlan.Add("- Right-click the newly created msExchPFTree object and select Properties")
                $actionPlan.Add("- On the Attribute Editor tab, click msExchPFTreeType, and then click Edit.")
                $actionPlan.Add("- In the Value box type 1, and then click OK two times.")
                $actionPlan.Add("- Exit and wait for AD Replication")
            } else {
                $actionPlan.Add("Validate permissions are inherited to object `"$($exceptionADOperationFailedAlreadyExist.Matches.Groups[2])`" and that there aren't any denies that shouldn't be there")
            }
            return
        }

        $foundKnownIssue = $false
        $diagnosticContext.Add("KnownOrganizationPreparationErrors - no known issue")
    }
    end {
        return [PSCustomObject]@{
            DiagnosticContext = $diagnosticContext
            DisplayContext    = $displayContext
            FoundKnownIssue   = $foundKnownIssue
            ActionPlan        = $actionPlan
            ErrorContext      = $errorContext
            WriteErrorContext = $writeErrorContext
            WriteWarning      = $writeWarning
        }
    }
}
