# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-ActionPlan.ps1
. $PSScriptRoot\..\New-ErrorContext.ps1
Function Test-ExceptionADOperationFailedAlreadyExist {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $ErrorContext
    )
    process {
        $errorContext = $ErrorContext.ErrorContext
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

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

        Write-Verbose "exceptionADOperationFailedAlreadyExist wasn't found in the file"
    }
}
