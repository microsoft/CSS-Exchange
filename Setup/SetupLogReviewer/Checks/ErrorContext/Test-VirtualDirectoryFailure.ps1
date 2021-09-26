# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-ActionPlan.ps1
. $PSScriptRoot\..\New-ErrorContext.ps1
Function Test-VirtualDirectoryFailure {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $ErrorContext
    )
    process {
        $errorContext = $ErrorContext.ErrorContext
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $issueDetected = $true
        $selectString = $errorContext | Select-String -Pattern "\[ERROR\] The virtual directory '.+' already exists under"

        if ($null -ne $selectString) {
            Write-Verbose "Found issue with virtual directory already exists."
            return
        }

        $selectString = $errorContext | Select-String -Pattern "\[ERROR\] The operation couldn't be performed because object '.+(?(Default Web Site | Exchange Back End))' couldn't be found on"

        if ($null -ne $selectString) {
            Write-Verbose "Found issue virtual directory couldn't be found"
            return
        }

        $selectString = $errorContext | Select-String -Pattern "\[ERROR\] Process execution failed with exit code"
        $appCmd = $errorContext | Select-String -Pattern "System32\\inetsrv\\appcmd.exe"

        if ($null -ne $selectString -and
            $null -ne $appCmd) {
            Write-Verbose "Found issue virtual directory - appcmd.exe failure"
            return
        }

        Write-Verbose "No Virtual directory issue detected."
        $issueDetected = $false
    }
    end {
        if ($issueDetected) {
            $errorContext |
                New-ErrorContext

            New-ActionPlan @(
                "Run SetupAssist on the server and address the issues it calls out with the virtual directories."
            )
        }
    }
}
