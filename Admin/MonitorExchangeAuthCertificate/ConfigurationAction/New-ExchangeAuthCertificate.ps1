# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\DataCollection\Get-ExchangeServerCertificate.ps1
. $PSScriptRoot\..\..\..\Shared\ActiveDirectoryFunctions\Get-InternalTransportCertificateFromServer.ps1
. $PSScriptRoot\..\..\..\Shared\CertificateFunctions\Import-ExchangeCertificateFromRawData.ps1
. $PSScriptRoot\..\..\..\Shared\Invoke-CatchActionError.ps1

function New-ExchangeAuthCertificate {
    [CmdletBinding(DefaultParameterSetName = "NewPrimaryAuthCert", SupportsShouldProcess = $true, ConfirmImpact = "High")]
    [OutputType([System.Object])]
    param(
        [Parameter(Mandatory = $false, ParameterSetName = "NewPrimaryAuthCert")]
        [switch]$ReplaceExpiredAuthCertificate,

        [Parameter(Mandatory = $false, ParameterSetName = "NewNextAuthCert")]
        [switch]$ConfigureNextAuthCertificate,

        [Parameter(Mandatory = $true, ParameterSetName = "NewNextAuthCert")]
        [int]$CurrentAuthCertificateLifetimeInDays,

        [Parameter(Mandatory = $false, ParameterSetName = "NewPrimaryAuthCert")]
        [Parameter(Mandatory = $false, ParameterSetName = "NewNextAuthCert")]
        [ScriptBlock]$CatchActionFunction
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        function GetCertificateBoundToDefaultWebSiteThumbprints {
            [CmdletBinding()]
            param()

            <#
                Returns the thumbprint of the certificate which is bound to the 'Default Web Site' in IIS
            #>

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"

            try {
                # Remove empty elements from array as they could be returned if no certificate is bound to a binding in between, then sort
                # the array and remove duplicates.
                $hashes = ((Get-Website -Name "Default Web Site" -ErrorAction Stop).bindings.collection.CertificateHash) | Where-Object {
                    $_
                } | Sort-Object -Unique
            } catch {
                Write-Verbose ("Unable to query 'Default Web Site' SSL binding information")
                Invoke-CatchActionError $CatchActionFunction
            }

            return $hashes
        }

        function GenerateNewAuthCertificate {
            [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
            [OutputType([System.Object])]
            param()

            <#
                Generates a new Auth Certificate which can then be configured via 'Set-AuthConfig'
                Returns a PSCustomObject with the information of the newly generated certificate
                which can then be consumed by the next function which configures the certificate as
                new Auth Certificate.
            #>

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"
            $confirmationMessage = "The following actions will be performed without the need to reconfirm:" +
            "`r`n    - The internal transport certificate will be queried" +
            "`r`n    - A new certificate will be generated, it overrides the internal transport certificate" +
            "`r`n    - The internal transport certificate will be set back to the previous one" +
            "`r`n      or" +
            "`r`n    - A new internal transport certificate will be generated if the previous one is invalid"

            $operationSuccessful = $false
            $internalTransportCertificateFoundOnServer = $false
            $errorCount = $Error.Count

            $authCertificateFriendlyName = ("Microsoft Exchange Server Auth Certificate - $(Get-Date -Format yyyyMMddhhmmss)")

            try {
                $newInternalTransportCertificateParams = @{
                    Server               = $env:COMPUTERNAME
                    KeySize              = 2048
                    PrivateKeyExportable = $true
                    FriendlyName         = $env:COMPUTERNAME
                    DomainName           = $env:COMPUTERNAME
                    IncludeServerFQDN    = $true
                    Services             = "SMTP"
                    Force                = $true
                    ErrorAction          = "Stop"
                }

                $newAuthCertificateParams = @{
                    Server               = $env:COMPUTERNAME
                    KeySize              = 2048
                    PrivateKeyExportable = $true
                    SubjectName          = "cn=Microsoft Exchange Server Auth Certificate"
                    FriendlyName         = $authCertificateFriendlyName
                    DomainName           = @()
                    ErrorAction          = "Stop"
                }

                if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, $confirmationMessage, "Unattended Exchange certificate generation")) {
                    Write-Verbose ("Internal transport certificate will be overwritten for a short time and then reset to the previous one")
                    $internalTransportCertificate = Get-InternalTransportCertificateFromServer $env:COMPUTERNAME
                    $defaultWebSiteCertificateThumbprints = GetCertificateBoundToDefaultWebSiteThumbprints
                    [string]$internalTransportCertificateThumbprint = $internalTransportCertificate.Thumbprint

                    if (($null -ne $internalTransportCertificate) -and
                        ($null -ne $defaultWebSiteCertificateThumbprints)) {
                        $newAuthCertificateParams.Add("Force", $true)
                        $servicesToEnable = $null
                        $servicesToEnableList = New-Object 'System.Collections.Generic.List[object]'
                        try {
                            $internalTransportCertificate = Get-ExchangeServerCertificate -Server $env:COMPUTERNAME -Thumbprint $internalTransportCertificateThumbprint -ErrorAction Stop

                            if ($null -ne $internalTransportCertificate) {
                                $internalTransportCertificateFoundOnServer = $true
                                $isInternalTransportBoundToIisFe = $defaultWebSiteCertificateThumbprints.Contains($internalTransportCertificateThumbprint)

                                if (($null -ne $internalTransportCertificate.Services) -and
                                    ($internalTransportCertificate.Services -ne 0)) {
                                    $transportCertificateServices = ($internalTransportCertificate.Services).ToString().ToUpper().Split(",").Trim()
                                    if ($transportCertificateServices.Count -eq 1) {
                                        # Use the Add() method if only one service is bound to the transport certificate
                                        $servicesToEnableList.Add($transportCertificateServices)
                                    } else {
                                        # Use the AddRange() method otherwise
                                        $servicesToEnableList.AddRange($transportCertificateServices)
                                    }

                                    # Make sure to remove IIS from list if the certificate was not bound to Front End Website before
                                    if (($isInternalTransportBoundToIisFe -eq $false) -and
                                        ($servicesToEnableList.Contains("IIS"))) {
                                        Write-Verbose ("Internal transport certificate is bound to Back End Website - avoid to enable it for IIS to prevent it being bound to Front End")
                                        $servicesToEnableList.Remove("IIS")
                                    }
                                } elseif ($null -eq $internalTransportCertificate.Services) {
                                    Write-Verbose ("No service information returned for internal transport certificate")
                                    if ($isInternalTransportBoundToIisFe) {
                                        Write-Verbose ("Internal transport certificate was bound to Front-End Website and will be rebound to it again")
                                        $servicesToEnableList.Add("IIS")
                                    }
                                    $servicesToEnableList.Add("SMTP")
                                }

                                $servicesToEnable = $([string]::Join(", ", $servicesToEnableList))
                            }
                        } catch {
                            Invoke-CatchActionError $CatchActionFunction
                            Write-Verbose ("Internal transport certificate wasn't detected on server: $($env:COMPUTERNAME)")
                            Write-Verbose ("We will generate a new internal transport certificate now")
                            try {
                                if ($PSCmdlet.ShouldProcess("New-ExchangeCertificate", "Generate new internal transport certificate")) {
                                    $newSelfSignedTransportCertificate = New-ExchangeCertificate @newInternalTransportCertificateParams
                                    if ($null -ne $newSelfSignedTransportCertificate) {
                                        $internalTransportCertificateFoundOnServer = $true
                                        if ($null -ne $newSelfSignedTransportCertificate.Thumbprint) {
                                            Write-Verbose ("Certificate object successfully deserialized")
                                            [string]$internalTransportCertificateThumbprint = $newSelfSignedTransportCertificate.Thumbprint
                                        } else {
                                            Write-Verbose ("Looks like deserialization of the certificate object failed - trying to import from RawData")
                                            [string]$internalTransportCertificateThumbprint = (Import-ExchangeCertificateFromRawData $newSelfSignedTransportCertificate).Thumbprint
                                            if ($null -ne $internalTransportCertificateThumbprint) {
                                                Write-Verbose ("Import from RawData was successful")
                                            } else {
                                                throw ("Import from RawData failed")
                                            }
                                        }

                                        Write-Verbose ("A new internal transport certificate with thumbprint: $($internalTransportCertificateThumbprint) was generated")
                                        $servicesToEnable = "SMTP"
                                    }
                                } else {
                                    $newInternalTransportCertificateParams.GetEnumerator() | ForEach-Object {
                                        Write-Host ("What if: Key: $($_.key) - Value: $($_.value)")
                                    }
                                }
                            } catch {
                                Write-Verbose ("Hit an exception while trying to generate a new internal transport certificate - Exception: $(Error[0].Exception.Message)")
                                Invoke-CatchActionError $CatchActionFunction
                            }
                        }
                    }
                }

                Write-Verbose ("Starting Auth Certificate creation process")
                try {
                    if ($PSCmdlet.ShouldProcess("New-ExchangeCertificate", "Generate new Auth Certificate")) {
                        $newAuthCertificate = New-ExchangeCertificate @newAuthCertificateParams
                        Start-Sleep -Seconds 5
                    } else {
                        $newAuthCertificateParams.GetEnumerator() | ForEach-Object {
                            Write-Host ("What if: Key: $($_.key) - Value: $($_.value)")
                        }
                        # Create dummy object to pass the following checks if -WhatIf was used as we don't create a new certificate in this mode
                        $newAuthCertificate = @{
                            Thumbprint = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234"
                        }
                    }
                } catch {
                    Write-Verbose ("Hit an exception while trying to generate a new Exchange Server Auth Certificate - Exception: $($Error[0].Exception.Message)")
                    Invoke-CatchActionError $CatchActionFunction
                }

                if ($internalTransportCertificateFoundOnServer) {
                    if ($PSCmdlet.ShouldProcess("Certificate: $internalTransportCertificateThumbprint on: $env:COMPUTERNAME for: $servicesToEnable", "Enable-ExchangeCertificate")) {
                        Write-Verbose ("Resetting internal transport certificate back to previous one")
                        Enable-ExchangeCertificate -Server $env:COMPUTERNAME -Thumbprint $internalTransportCertificateThumbprint -Services $servicesToEnable -Force | Out-Null
                        Start-Sleep -Seconds 10
                        Write-Verbose ("Internal transport certificate was reset back to: $((Get-InternalTransportCertificateFromServer $env:COMPUTERNAME).Thumbprint)")
                    }
                }

                if ($null -ne $newAuthCertificate) {
                    $operationSuccessful = $true
                    if ($null -ne $newAuthCertificate.Thumbprint) {
                        Write-Verbose ("Certificate object successfully deserialized")
                        [string]$newAuthCertificateThumbprint = $newAuthCertificate.Thumbprint
                    } else {
                        Write-Verbose ("Looks like deserialization of the certificate object failed - trying to import from RawData")
                        [string]$newAuthCertificateThumbprint = (Import-ExchangeCertificateFromRawData $newAuthCertificate).Thumbprint
                        if ($null -ne $newAuthCertificateThumbprint) {
                            Write-Verbose ("Import from RawData was successful")
                        } else {
                            throw ("Import from RawData failed")
                        }
                    }
                    Write-Verbose ("New Auth Certificate was successfully created. Thumbprint: $($newAuthCertificateThumbprint)")
                }
            } catch {
                Write-Verbose ("We hit an exception during Auth Certificate creation process - Exception: $($Error[0].Exception.Message)")
                Invoke-CatchActionError $CatchActionFunction
            }

            return [PSCustomObject]@{
                ComputerName                = $env:COMPUTERNAME
                InternalTransportThumbprint = $internalTransportCertificateThumbprint
                FriendlyName                = $authCertificateFriendlyName
                Thumbprint                  = $newAuthCertificateThumbprint
                Successful                  = $operationSuccessful
                ErrorOccurred               = if ($Error.Count -gt $errorCount) { $($Error[0].Exception.Message) }
            }
        }

        function ConfigureNextAuthCertificate {
            [CmdletBinding()]
            [OutputType([System.Object])]
            param(
                [int]$CurrentAuthCertificateLifetimeInDays,
                [int]$EnableDaysInFuture = 30
            )

            <#
                We must generate a new self-signed certificate and set it as new certificate by the help of the
                -NewCertificateThumbprint parameter. We must also specify a DateTime (via -NewCertificateEffectiveDate)
                when the new certificate becomes active.

                Returns $true if renewal was successful, returns $false if it wasn't
            #>

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"

            $renewalSuccessful = $false
            $newAuthCertificateObject = GenerateNewAuthCertificate
            $nextAuthCertificateActiveOn = (Get-Date).AddDays($EnableDaysInFuture)

            if ($null -ne $CurrentAuthCertificateLifetimeInDays) {
                Write-Verbose ("Current Auth Certificate will expire in: $($CurrentAuthCertificateLifetimeInDays) days")

                if ($CurrentAuthCertificateLifetimeInDays -lt ($EnableDaysInFuture + 2)) {
                    Write-Verbose ("Need to re-calculate the EnableDaysInFuture value to ensure a smooth Auth Certificate rotation")
                    # Assuming that there is not much time (< 2 days) until the current Auth Certificate expires,
                    # the next Auth Certificate should become active as soon as the AuthAdmin servicelet runs on the server
                    $EnableDaysInFuture = 0

                    if (($CurrentAuthCertificateLifetimeInDays - 4) -gt 0) {
                        $EnableDaysInFuture = 4
                    } elseif (($CurrentAuthCertificateLifetimeInDays - 2) -gt 0) {
                        $EnableDaysInFuture = 2
                    }

                    $nextAuthCertificateActiveOn = (Get-Date).AddDays($EnableDaysInFuture)
                    Write-Verbose ("The new Auth Certificate will become active in: $($EnableDaysInFuture) days")
                } else {
                    Write-Verbose ("There is enough time to initiate the Auth Certificate rotation - no need to adjust EnableDaysInFuture")
                }
            }

            if (($null -ne $newAuthCertificateObject) -and
                ($newAuthCertificateObject.Successful)) {
                [string]$newAuthCertificateThumbprint = $newAuthCertificateObject.Thumbprint
                Write-Verbose ("New Auth Certificate with thumbprint: $($newAuthCertificateThumbprint) generated - the new one will replace the existing one in: $($EnableDaysInFuture) days")
                try {
                    Write-Verbose ("[Required] Step 1: Set certificate: $($newAuthCertificateThumbprint) as the next Auth Certificate")
                    if ($PSCmdlet.ShouldProcess("Certificate: $newAuthCertificateThumbprint Date: $nextAuthCertificateActiveOn", "Set-AuthConfig")) {
                        $setAuthConfigParams = @{
                            NewCertificateThumbprint    = $newAuthCertificateThumbprint
                            NewCertificateEffectiveDate = if ($EnableDaysInFuture -eq 0) { Get-Date } else { $nextAuthCertificateActiveOn }
                            Force                       = $true
                            ErrorAction                 = "Stop"
                        }
                        Set-AuthConfig @setAuthConfigParams
                    }

                    if ($EnableDaysInFuture -eq 0) {
                        # Restart MSExchangeServiceHost service to ensure that the new Auth Certificate is used immediately as don't have time
                        # to wait until the AuthAdmin servicelet runs on the server due to the limited time until the current Auth Certificate expires
                        Write-Verbose ("[Optional] Step 2: Restart service 'MSExchangeServiceHost' on computer: $($env:COMPUTERNAME)")
                        Restart-Service -Name "MSExchangeServiceHost" -ErrorAction Stop
                    }
                    Write-Verbose ("Done - Certificate: $($newAuthCertificateThumbprint) set as the next Auth Certificate")
                    Write-Verbose ("Effective date is: $($nextAuthCertificateActiveOn)")
                    $renewalSuccessful = $true
                } catch {
                    Write-Verbose ("Error while enabling the next Auth Certificate. Error: $($Error[0].Exception.Message)")
                    Invoke-CatchActionError $CatchActionFunction
                }
            }

            return [PSCustomObject]@{
                RenewalSuccessful           = $renewalSuccessful
                NextCertificateActiveOnDate = $nextAuthCertificateActiveOn
                NewCertificateThumbprint    = $newAuthCertificateThumbprint
            }
        }

        function ReplaceExpiredAuthCertificate {
            [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
            [OutputType([System.Object])]
            param()

            <#
                We must generate a new self-signed certificate and replace the existing Auth Certificate
                if it's already expired. We must also set it as active by specifying the current DateTime via
                -NewCertificateEffectiveDate parameter.
                To speed things up, restarting 'MSExchangeServiceHost' service is needed as well as 'MSExchangeOWAAppPool'
                and 'MSExchangeECPAppPool' app pools. However, it shouldn't become a problem if restarting the service or
                app pools fails.

                Returns $true if renewal was successful, returns $false if it wasn't
            #>

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"
            $newAuthCertificateActiveOn = $null
            $renewalSuccessful = $false
            $newAuthCertificateObject = GenerateNewAuthCertificate

            if (($null -ne $newAuthCertificateObject) -and
                ($newAuthCertificateObject.Successful)) {
                [string]$newAuthCertificateThumbprint = $newAuthCertificateObject.Thumbprint
                Write-Verbose ("New Auth Certificate with thumbprint: $($newAuthCertificateThumbprint) generated - the existing one will be replaced immediately with the new one")
                try {
                    Write-Verbose ("[Required] Step 1: Set certificate: $($newAuthCertificateThumbprint) as new Auth Certificate")
                    if ($PSCmdlet.ShouldProcess("Certificate: $newAuthCertificateThumbprint Date: immediately", "Set-AuthConfig")) {
                        # We must use Get-Date here to ensure that the date which is passed to NewCertificateEffectiveDate parameter is a valid one
                        $setAuthConfigParams = @{
                            NewCertificateThumbprint    = $newAuthCertificateThumbprint
                            NewCertificateEffectiveDate = ($newAuthCertificateActiveOn = Get-Date)
                            Force                       = $true
                            ErrorAction                 = "Stop"
                        }
                        Set-AuthConfig @setAuthConfigParams
                    }

                    Write-Verbose ("[Required] Step 2: Publish the new Auth Certificate")
                    if ($PSCmdlet.ShouldProcess("PublishCertificate", "Set-AuthConfig")) {
                        Set-AuthConfig -PublishCertificate -ErrorAction Stop
                    }

                    Write-Verbose ("[Required] Step 3: Clear previous Auth Certificate")
                    if ($PSCmdlet.ShouldProcess("ClearPreviousCertificate", "Set-AuthConfig")) {
                        Set-AuthConfig -ClearPreviousCertificate -ErrorAction Stop
                    }

                    try {
                        # Run these commands in a separate try / catch as it isn't a terminating issue if they fail
                        Write-Verbose ("[Optional] Step 4: Restart service 'MSExchangeServiceHost' on computer: $($env:COMPUTERNAME)")
                        Restart-Service -Name "MSExchangeServiceHost" -ErrorAction Stop

                        if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Restart-WebAppPool")) {
                            Write-Verbose ("[Optional] Step 5: Restart WebApp Pools 'MSExchangeOWAAppPool' and 'MSExchangeECPAppPool' on computer $($env:COMPUTERNAME)")
                            Restart-WebAppPool -Name "MSExchangeOWAAppPool" -ErrorAction Stop
                            Restart-WebAppPool -Name "MSExchangeECPAppPool" -ErrorAction Stop
                        }
                    } catch {
                        Write-Warning ("Error while restarting service 'MSExchangeServiceHost' or WebApp Pools")
                        Write-Warning ("However, these steps are optional and not required - the Auth Certificate was replaced with a new one")
                        Invoke-CatchActionError $CatchActionFunction
                    }

                    Write-Verbose ("Done - Certificate: $($newAuthCertificateThumbprint) is the new Auth Certificate")
                    $renewalSuccessful = $true
                } catch {
                    Write-Verbose ("Error while enabling the new Auth Certificate - Exception: $($Error[0].Exception.Message)")
                    Invoke-CatchActionError $CatchActionFunction
                }
            }

            return [PSCustomObject]@{
                RenewalSuccessful           = $renewalSuccessful
                NextCertificateActiveOnDate = $newAuthCertificateActiveOn
                NewCertificateThumbprint    = $newAuthCertificateThumbprint
            }
        }
    }
    process {
        if ($ReplaceExpiredAuthCertificate) {
            Write-Verbose ("Calling function to replace an already expired or invalid Auth Certificate")
            $renewalActionPerformed = ReplaceExpiredAuthCertificate
        } elseif ($ConfigureNextAuthCertificate) {
            Write-Verbose ("Calling function to state the next Auth Certificate for rotation")
            $renewalActionPerformed = ConfigureNextAuthCertificate -CurrentAuthCertificateLifetimeInDays $CurrentAuthCertificateLifetimeInDays
        } else {
            Write-Verbose ("No Auth Certificate configuration action was specified")
        }
    }
    end {
        return [PSCustomObject]@{
            RenewalActionPerformed        = ($renewalActionPerformed.RenewalSuccessful -eq $true)
            AuthCertificateActivationDate = ($renewalActionPerformed.NextCertificateActiveOnDate)
            NewCertificateThumbprint      = ($renewalActionPerformed.NewCertificateThumbprint)
        }
    }
}
