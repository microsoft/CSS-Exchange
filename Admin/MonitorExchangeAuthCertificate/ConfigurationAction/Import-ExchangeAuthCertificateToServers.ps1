# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\Invoke-CatchActionError.ps1

function Import-ExchangeAuthCertificateToServers {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ExportFromServer = $env:COMPUTERNAME,

        [Parameter(Mandatory = $true)]
        [string]$Thumbprint,

        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[string]]$ServersToImportList,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    <#
        This function can be used to export an Exchange Certificate as byte array and import it to a list of servers
        which were passed to this function via ServersToImportList parameter.
        The function returns a PSCustomObject with the following properties:
            - ExportSuccessful : Indicator if the certificate was successfully exported on the source server (where the script runs)
            - ImportToAllServersSuccessful : Indicator if the certificate was successfully imported to all servers
            - Thumbprint : Thumbprint of the certificate that was imported
            - ImportedToServersList : List of all servers on which the certificate was successfully imported
            - ImportToServersFailedList : List of all serves on which the certificate import failed for whatever reason
    #>

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $exportSuccessful = $false
        $importFailedList = New-Object "System.Collections.Generic.List[string]"
        $importSuccessfulList = New-Object "System.Collections.Generic.List[string]"
    }
    process {
        try {
            # Generate a temporary password to protect the exported private key in memory and on transport
            $bytes = [System.Byte[]]::new(64)
            ([System.Security.Cryptography.RandomNumberGenerator]::Create()).GetBytes($bytes)
            $secureString = [System.Security.SecureString]::new()
            foreach ($b in $bytes) {
                $secureString.AppendChar([char]$b)
            }
            $secureString.MakeReadOnly()
            $bytes = $null

            if ($PSCmdlet.ShouldProcess($Thumbprint, "Export-ExchangeCertificate")) {
                # Export the certificate as byte array as we need to pass this to the Import-ExchangeCertificate cmdlet
                $exportExchangeCertificateParams = @{
                    Server        = $ExportFromServer
                    Thumbprint    = $Thumbprint
                    BinaryEncoded = $true
                    Password      = $secureString
                    ErrorAction   = "Stop"
                }
                $exportedAuthCertificate = Export-ExchangeCertificate @exportExchangeCertificateParams
            }

            if (($null -ne $exportedAuthCertificate.FileData) -or
                ($WhatIfPreference)) {
                Write-Verbose ("Certificate with thumbprint: $Thumbprint successfully exported")
                $exportSuccessful = $true

                # Next step is to import the certificate to all Exchange servers passed via $ServersToImportList parameter
                foreach ($server in $ServersToImportList) {
                    try {
                        if ($PSCmdlet.ShouldProcess($server, "Import-ExchangeCertificate")) {
                            $importExchangeCertificateParams = @{
                                Server               = $server
                                FileData             = $exportedAuthCertificate.FileData
                                Password             = $secureString
                                PrivateKeyExportable = $true
                                ErrorAction          = "Stop"
                            }
                            Import-ExchangeCertificate @importExchangeCertificateParams
                        }
                        Write-Verbose ("Certificate import to server: $server was successful")
                        $importSuccessfulList.Add($server)
                    } catch {
                        Write-Verbose ("Unable to import the certificate to server: $server - Exception: $($Error[0].Exception.Message)")
                        $importFailedList.Add($server)
                        Invoke-CatchActionError $CatchActionFunction
                    }
                }
            } else {
                Write-Verbose ("Unable to export the certificate with thumbprint: $Thumbprint")
            }
        } catch {
            Write-Verbose ("Something went wrong - Exception: $($Error[0].Exception.Message)")
            Invoke-CatchActionError $CatchActionFunction
        }
    }
    end {
        $exportedAuthCertificate = $null
        $secureString.Dispose()
        return [PSCustomObject]@{
            ExportSuccessful             = $exportSuccessful
            ImportToAllServersSuccessful = (($importFailedList.Count -eq 0) -and ($exportSuccessful))
            Thumbprint                   = $Thumbprint
            ImportedToServersList        = $importSuccessfulList
            ImportToServersFailedList    = $importFailedList
        }
    }
}
