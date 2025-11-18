# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Invoke-CatchActionError.ps1

<#
.DESCRIPTION
    The Export-CertificateAndPrivateKey function uses .NET cryptography classes to securely export
    a certificate and its private key from either the LocalMachine or CurrentUser certificate store.
    If the specified computer name refers to the local host, the operation runs locally; otherwise,
    it uses PowerShell Remoting (Invoke-Command) to perform the export on the remote system.

    The exported certificate is returned as a byte array (PFX format) in memory only
    no files are written to disk. The private key must be marked as exportable, and
    the caller must have appropriate permissions to access it.
#>
function Export-CertificateAndPrivateKey {
    [CmdletBinding()]
    [OutputType([System.Byte[]])]
    param(
        [string]$ComputerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $true)]
        [string]$Thumbprint,

        [Parameter(Mandatory = $true)]
        [SecureString]$Password,

        [ValidateSet("CurrentUser", "LocalMachine")]
        [string]$Store = "LocalMachine",

        [ScriptBlock]$CatchActionFunction
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    $certificateOperationScriptBlock = {
        param(
            [string]$InThumbprint,
            [SecureString]$InPassword,
            [string]$InStore
        )

        $certificateStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", $($InStore))
        $certificateStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

        $certificate = $certificateStore.Certificates | Where-Object { $_.Thumbprint -eq $InThumbprint }

        if (-not $certificate) {
            throw "Certificate with thumbprint $InThumbprint not found in $InStore\My"
        }

        if (-not $certificate.HasPrivateKey) {
            throw "Certificate with thumbprint $InThumbprint doesn't have a private key"
        }

        try {
            $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $InPassword)
        } catch {
            throw "The private key couldn't be exported. It either couldn't be accessed or isn't exportable: $_"
        } finally {
            $certificateStore.Close()
        }
    }

    $arguments = @($Thumbprint, $Password, $Store)

    try {
        if ($ComputerName -eq $env:COMPUTERNAME -or
            $ComputerName -eq "localhost") {
            Write-Verbose "Exporting from the local computer"
            $pfxByteArray = & $certificateOperationScriptBlock @arguments
        } else {
            Write-Verbose "Exporting from a remote computer: $ComputerName"
            $pfxByteArray = Invoke-Command -ComputerName $ComputerName -ScriptBlock $certificateOperationScriptBlock -ArgumentList $arguments -ErrorAction Stop
        }
    } catch {
        Write-Verbose "Hit an issue while executing the script block: $_"
        Invoke-CatchActionError $CatchActionFunction
    }

    if ($pfxByteArray) {
        Write-Verbose "Certificate was successfully exported as bytes array"
        return $pfxByteArray
    }

    Write-Verbose "No certificate was exported"
    return $null
}
