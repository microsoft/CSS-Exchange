# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-ErrorContext.ps1
. $PSScriptRoot\..\New-WriteObject.ps1
Function Write-LastErrorInformation {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $SetupLogReviewer
    )
    process {
        $lastErrorInfo = $SetupLogReviewer | GetFirstErrorWithContextToLine -1 30 200

        if ($null -ne $lastErrorInfo) {
            New-WriteObject "Failed to determine known cause, but here is your error context that we are seeing" -WriteType "Error"
            $lastErrorInfo |
                Where-Object { -not [string]::IsNullOrEmpty($_) } |
                New-ErrorContext
        }

        New-WriteObject "Looks like we weren't able to determine the cause of the issue with Setup. Please run SetupAssist.ps1 on the server."
        New-WriteObject "If that doesn't find the cause, please notify 'ExToolsFeedback@microsoft.com' to help us improve the scripts."
    }
}
