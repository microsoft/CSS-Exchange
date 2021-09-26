# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-ActionPlan.ps1
. $PSScriptRoot\..\New-ErrorContext.ps1
Function Test-MSExchangeSecurityGroupsContainerDeleted {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $ErrorContext
    )
    process {
        $errorContext = $ErrorContext.ErrorContext
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $msExchangeSecurityGroupsContainerDeleted = $errorContext | Select-String -Pattern "System.NullReferenceException: Object reference not set to an instance of an object.", `
            "Microsoft.Exchange.Management.Tasks.InitializeExchangeUniversalGroups.CreateOrMoveEWPGroup\(ADGroup ewp, ADOrganizationalUnit usgContainer\)"

        if ($null -ne $msExchangeSecurityGroupsContainerDeleted) {
            Write-Verbose "Found matching patterns - msExchangeSecurityGroupsContainerDeleted"

            if ($msExchangeSecurityGroupsContainerDeleted[0].Pattern -ne $msExchangeSecurityGroupsContainerDeleted[1].Pattern -and
                $msExchangeSecurityGroupsContainerDeleted[0].LineNumber -eq ($msExchangeSecurityGroupsContainerDeleted[1].LineNumber - 1)) {
                $newErrorContext = @()
                $newErrorContext += $msExchangeSecurityGroupsContainerDeleted[0].Line
                $newErrorContext += $msExchangeSecurityGroupsContainerDeleted[1].Line
                $newErrorContext | New-ErrorContext
                Write-Verbose "Matched additional information"
                New-ActionPlan "'OU=Microsoft Exchange Security Groups' was deleted from the root of the domain. We need to have it created again at the root of the domain to continue."
                return
            }
            Write-Verbose "Failed to match additional patterns"
        }

        Write-Verbose "msExchangeSecurityGroupsContainerDeleted wasn't found in log"
    }
}
