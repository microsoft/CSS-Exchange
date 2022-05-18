# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-ActionPlan.ps1
. $PSScriptRoot\..\New-ErrorContext.ps1
function Test-MultiActiveSyncVirtualDirectories {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $ErrorRefAndSetupLog
    )
    process {
        $errorReference = $ErrorRefAndSetupLog.ErrorReference
        $setupLogReviewer = $ErrorRefAndSetupLog.SetupLogReviewer
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        if ($errorReference.Matches.Groups[1].Value -eq "CafeComponent___e1130a139a734d90b6c5eec88868fbe9") {
            Write-Verbose "Known issue with Multiple Active Sync Virtual Directories"
            $errorContext = $setupLogReviewer | GetFirstErrorWithContextToLine $errorReference.LineNumber 1
            $multiVDirs = $errorContext | Select-String -Pattern "Cannot convert 'System.Object\[\]' to the type 'Microsoft.Exchange.Configuration.Tasks.VirtualDirectoryIdParameter'"

            if ($null -ne $multiVDirs) {
                Write-Verbose "Found Multiple Virtual Directories"
                $errorContext |
                    New-ErrorContext

                New-ActionPlan @(
                    "- Remove the secondary virtual directory that is custom on the server."
                    "- NOTE: You should only return one value when running the following cmdlet on the server:"
                    "        Get-ActiveSyncVirtualDirectory -Server `$env:ComputerName"
                )
            } else {
                Write-Verbose "Failed to find typical presentation of the issue"
            }
        }
    }
}
