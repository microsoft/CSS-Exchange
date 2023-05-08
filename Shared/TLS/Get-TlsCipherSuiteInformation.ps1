# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Invoke-ScriptBlockHandler.ps1
. $PSScriptRoot\..\Get-RemoteRegistryValue.ps1

function Get-TlsCipherSuiteInformation {
    [OutputType("System.Object")]
    param(
        [string]$MachineName = $env:COMPUTERNAME,
        [ScriptBlock]$CatchActionFunction
    )

    begin {

        function GetProtocolNames {
            param(
                [int[]]$Protocol
            )
            $protocolNames = New-Object System.Collections.Generic.List[string]

            foreach ($p in $Protocol) {
                $name = [string]::Empty

                if ($p -eq 2) { $name = "SSL_2_0" }
                elseif ($p -eq 768) { $name = "SSL_3_0" }
                elseif ($p -eq 769) { $name = "TLS_1_0" }
                elseif ($p -eq 770) { $name = "TLS_1_1" }
                elseif ($p -eq 771) { $name = "TLS_1_2" }
                elseif ($p -eq 772) { $name = "TLS_1_3" }
                elseif ($p -eq 32528) { $name = "TLS_1_3_DRAFT_16" }
                elseif ($p -eq 32530) { $name = "TLS_1_3_DRAFT_18" }
                elseif ($p -eq 65279) { $name = "DTLS_1_0" }
                elseif ($p -eq 65277) { $name = "DTLS_1_1" }
                else {
                    Write-Verbose "Unable to determine protocol $p"
                    $name = $p
                }

                $protocolNames.Add($name)
            }
            return [string]::Join(" & ", $protocolNames)
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $tlsCipherReturnObject = New-Object 'System.Collections.Generic.List[object]'
    }
    process {
        # 'Get-TlsCipherSuite' takes account of the cipher suites which are configured by the help of GPO.
        # No need to query the ciphers defined via GPO if this call is successful.
        Write-Verbose "Trying to query TlsCipherSuites via 'Get-TlsCipherSuite'"
        $getTlsCipherSuiteParams = @{
            ComputerName        = $MachineName
            ScriptBlock         = { Get-TlsCipherSuite }
            CatchActionFunction = $CatchActionFunction
        }
        $tlsCipherSuites = Invoke-ScriptBlockHandler @getTlsCipherSuiteParams

        if ($null -eq $tlsCipherSuites) {
            # If we can't get the ciphers via cmdlet, we need to query them via registry call and need to check
            # if ciphers suites are defined via GPO as well. If there are some, these take precedence over what
            # is in the default location.
            Write-Verbose "Failed to query TlsCipherSuites via 'Get-TlsCipherSuite' fallback to registry"

            $policyTlsRegistryParams = @{
                MachineName         = $MachineName
                SubKey              = "SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
                GetValue            = "Functions"
                ValueType           = "String"
                CatchActionFunction = $CatchActionFunction
            }

            Write-Verbose "Trying to query cipher suites configured via GPO from registry"
            $policyDefinedCiphers = Get-RemoteRegistryValue @policyTlsRegistryParams

            if ($null -ne $policyDefinedCiphers) {
                Write-Verbose "Ciphers specified via GPO found - these take precedence over what is in the default location"
                $tlsCipherSuites = $policyDefinedCiphers.Split(",")
            } else {
                Write-Verbose "No cipher suites configured via GPO found - going to query the local TLS cipher suites"
                $tlsRegistryParams = @{
                    MachineName         = $MachineName
                    SubKey              = "SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002"
                    GetValue            = "Functions"
                    ValueType           = "MultiString"
                    CatchActionFunction = $CatchActionFunction
                }

                $tlsCipherSuites = Get-RemoteRegistryValue @tlsRegistryParams
            }
        }

        if ($null -ne $tlsCipherSuites) {
            foreach ($cipher in $tlsCipherSuites) {
                $tlsCipherReturnObject.Add([PSCustomObject]@{
                        Name        = if ($null -eq $cipher.Name) { $cipher } else { $cipher.Name }
                        CipherSuite = if ($null -eq $cipher.CipherSuite) { "N/A" } else { $cipher.CipherSuite }
                        Cipher      = if ($null -eq $cipher.Cipher) { "N/A" } else { $cipher.Cipher }
                        Certificate = if ($null -eq $cipher.Certificate) { "N/A" } else { $cipher.Certificate }
                        Protocols   = if ($null -eq $cipher.Protocols) { "N/A" } else { (GetProtocolNames $cipher.Protocols) }
                    })
            }
        }
    }
    end {
        return $tlsCipherReturnObject
    }
}
