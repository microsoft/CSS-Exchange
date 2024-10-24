# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\Invoke-CatchActionError.ps1

function Test-IsServerValidForAuthCertificateGeneration {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [ScriptBlock]$CatchActionFunction
    )

    <#
        Validates that the server on which the script runs is a mailbox server running Exchange major version 15 or greater
    #>

    try {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $isValid = $false
        Write-Verbose ("Trying to query Exchange Server details")
        $exchangeServerDetails = Get-ExchangeServer -Identity $ComputerName -ErrorAction Stop

        if (($exchangeServerDetails.IsMailboxServer) -and
            (($exchangeServerDetails.AdminDisplayVersion -match "^Version 15"))) {
            Write-Verbose ("Exchange Server role and version is VALID to renew the Auth Certificate")
            $isValid = $true
        } else {
            Write-Verbose ("Exchange Server role or version is INVALID to renew the Auth Certificate")
        }
    } catch {
        Write-Verbose ("Unable to query Exchange Server details - Exception: $($Error[0].Exception.Message)")
        Invoke-CatchActionError $CatchActionFunction
    }

    return $isValid
}
