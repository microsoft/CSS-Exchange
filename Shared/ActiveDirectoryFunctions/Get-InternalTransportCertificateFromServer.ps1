# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-OrganizationContainer.ps1
. $PSScriptRoot\..\Invoke-CatchActionError.ps1

function Get-InternalTransportCertificateFromServer {
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param (
        [string]$ComputerName = $env:COMPUTERNAME,
        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    <#
        Reads the certificate set as internal transport certificate (aka default SMTP certificate) from AD.
        The certificate is specified on a per-server base.

        Returns the X509Certificate2 object if we were able to query it from AD, otherwise it returns $null.
    #>

    try {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $organizationContainer = Get-OrganizationContainer
        $exchangeServerPath = ("CN=" + $($ComputerName.Split(".")[0]) + ",CN=Servers,CN=Exchange Administrative Group (FYDIBOHF23SPDLT),CN=Administrative Groups," + $organizationContainer.distinguishedName)
        $exchangeServer = [ADSI]("LDAP://" + $exchangeServerPath)
        Write-Verbose "Exchange Server path: $($exchangeServerPath)"
        if ($null -ne $exchangeServer.msExchServerInternalTLSCert) {
            $certObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($exchangeServer.msExchServerInternalTLSCert)
            Write-Verbose ("Internal transport certificate on server: $($ComputerName) is: $($certObject.Thumbprint)")
        }
    } catch {
        Write-Verbose ("Unable to query the internal transport certificate - Exception: $($Error[0].Exception.Message)")
        Invoke-CatchActionError $CatchActionFunction
    }

    return $certObject
}
