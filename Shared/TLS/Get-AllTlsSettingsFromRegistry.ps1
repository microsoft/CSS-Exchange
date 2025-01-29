# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Get-RemoteRegistryValue.ps1
. $PSScriptRoot\..\ScriptBlockFunctions\RemotePipelineHandlerFunctions.ps1

function Get-AllTlsSettingsFromRegistry {
    [CmdletBinding()]
    param(
        [string]$MachineName = $env:COMPUTERNAME,
        [ScriptBlock]$CatchActionFunction
    )
    begin {

        function Get-TLSMemberValue {
            param(
                [Parameter(Mandatory = $true)]
                [string]
                $GetKeyType,

                [Parameter(Mandatory = $false)]
                [object]
                $KeyValue,

                [Parameter( Mandatory = $false)]
                [bool]
                $NullIsEnabled
            )
            Write-Verbose "KeyValue is null: '$($null -eq $KeyValue)' | KeyValue: '$KeyValue' | GetKeyType: $GetKeyType | NullIsEnabled: $NullIsEnabled"
            switch ($GetKeyType) {
                "Enabled" {
                    return ($null -eq $KeyValue -and $NullIsEnabled) -or ($KeyValue -ne 0 -and $null -ne $KeyValue)
                }
                "DisabledByDefault" {
                    return $null -ne $KeyValue -and $KeyValue -ne 0
                }
            }
        }

        function Get-NETDefaultTLSValue {
            param(
                [Parameter(Mandatory = $false)]
                [object]
                $KeyValue,

                [Parameter(Mandatory = $true)]
                [string]
                $NetVersion,

                [Parameter(Mandatory = $true)]
                [string]
                $KeyName
            )
            Write-Verbose "KeyValue is null: '$($null -eq $KeyValue)' | KeyValue: '$KeyValue' | NetVersion: '$NetVersion' | KeyName: '$KeyName'"
            return $null -ne $KeyValue -and $KeyValue -eq 1
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Write-Verbose "Passed - MachineName: '$MachineName'"
        $registryBase = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS {0}\{1}"
        $enabledKey = "Enabled"
        $disabledKey = "DisabledByDefault"
        $netRegistryBase = "SOFTWARE\{0}\.NETFramework\{1}"
        $allTlsObjects = [PSCustomObject]@{
            "TLS" = @{}
            "NET" = @{}
        }
    }
    process {
        foreach ($tlsVersion in @("1.0", "1.1", "1.2", "1.3")) {
            $registryServer = $registryBase -f $tlsVersion, "Server"
            $registryClient = $registryBase -f $tlsVersion, "Client"
            $baseParams = @{
                MachineName         = $MachineName
                CatchActionFunction = $CatchActionFunction
            }

            $serverEnabledValue = $null
            $serverDisabledByDefaultValue = $null
            $clientEnabledValue = $null
            $clientDisabledByDefaultValue = $null
            $serverEnabled = $null
            $serverDisabledByDefault = $null
            $clientEnabled = $null
            $clientDisabledByDefault = $null

            # Get the Enabled and DisabledByDefault values
            Get-RemoteRegistryValue @baseParams -SubKey $registryServer -GetValue $enabledKey |
                Invoke-RemotePipelineHandler -Result ([ref]$serverEnabledValue)
            Get-RemoteRegistryValue @baseParams -SubKey $registryServer -GetValue $disabledKey |
                Invoke-RemotePipelineHandler -Result ([ref]$serverDisabledByDefaultValue)
            Get-RemoteRegistryValue @baseParams -SubKey $registryClient -GetValue $enabledKey |
                Invoke-RemotePipelineHandler -Result ([ref]$clientEnabledValue)
            Get-RemoteRegistryValue @baseParams -SubKey $registryClient -GetValue $disabledKey |
                Invoke-RemotePipelineHandler -Result ([ref]$clientDisabledByDefaultValue)
            Get-TLSMemberValue -GetKeyType $enabledKey -KeyValue $serverEnabledValue -NullIsEnabled ($tlsVersion -ne "1.3") |
                Invoke-RemotePipelineHandler -Result ([ref]$serverEnabled)
            Get-TLSMemberValue -GetKeyType $disabledKey -KeyValue $serverDisabledByDefaultValue |
                Invoke-RemotePipelineHandler -Result ([ref]$serverDisabledByDefault)
            Get-TLSMemberValue -GetKeyType $enabledKey -KeyValue $clientEnabledValue -NullIsEnabled ($tlsVersion -ne "1.3") |
                Invoke-RemotePipelineHandler -Result ([ref]$clientEnabled)
            Get-TLSMemberValue -GetKeyType $disabledKey -KeyValue $clientDisabledByDefaultValue |
                Invoke-RemotePipelineHandler -Result ([ref]$clientDisabledByDefault)

            $disabled = $serverEnabled -eq $false -and ($serverDisabledByDefault -or $null -eq $serverDisabledByDefaultValue) -and
            $clientEnabled -eq $false -and ($clientDisabledByDefault -or $null -eq $clientDisabledByDefaultValue)
            $misconfigured = $serverEnabled -ne $clientEnabled -or $serverDisabledByDefault -ne $clientDisabledByDefault
            # only need to test server settings here, because $misconfigured will be set and will be the official status.
            # want to check for if Server is Disabled and Disabled By Default is not set or the reverse. This would be only part disabled
            # and not what we recommend on the blog post.
            $halfDisabled = ($serverEnabled -eq $false -and $serverDisabledByDefault -eq $false -and $null -ne $serverDisabledByDefaultValue) -or
            ($serverEnabled -and $serverDisabledByDefault)
            $configuration = "Enabled"

            if ($disabled) {
                Write-Verbose "TLS is Disabled"
                $configuration = "Disabled"
            }

            if ($halfDisabled) {
                Write-Verbose "TLS is only half disabled"
                $configuration = "Half Disabled"
            }

            if ($misconfigured) {
                Write-Verbose "TLS is misconfigured"
                $configuration = "Misconfigured"
            }

            $currentTLSObject = [PSCustomObject]@{
                TLSVersion                 = $tlsVersion
                "Server$enabledKey"        = $serverEnabled
                "Server$enabledKey`Value"  = $serverEnabledValue
                "Server$disabledKey"       = $serverDisabledByDefault
                "Server$disabledKey`Value" = $serverDisabledByDefaultValue
                "ServerRegistryPath"       = $registryServer
                "Client$enabledKey"        = $clientEnabled
                "Client$enabledKey`Value"  = $clientEnabledValue
                "Client$disabledKey"       = $clientDisabledByDefault
                "Client$disabledKey`Value" = $clientDisabledByDefaultValue
                "ClientRegistryPath"       = $registryClient
                "TLSVersionDisabled"       = $disabled
                "TLSMisconfigured"         = $misconfigured
                "TLSHalfDisabled"          = $halfDisabled
                "TLSConfiguration"         = $configuration
            }
            $allTlsObjects.TLS.Add($TlsVersion, $currentTLSObject)
        }

        foreach ($netVersion in @("v2.0.50727", "v4.0.30319")) {

            $msRegistryKey = $netRegistryBase -f "Microsoft", $netVersion
            $wowMsRegistryKey = $netRegistryBase -f "Wow6432Node\Microsoft", $netVersion
            $systemDefaultTlsVersionsValue = $null
            $schUseStrongCryptoValue = $null
            $wowSystemDefaultTlsVersionsValue = $null
            $wowSchUseStrongCryptoValue = $null
            $systemDefaultTlsVersions = $null
            $wowSystemDefaultTlsVersions = $null
            $schUseStrongCrypto = $null
            $wowSchUseStrongCrypto = $null

            $msRegistryKeyParams = @{
                MachineName         = $MachineName
                SubKey              = $msRegistryKey
                CatchActionFunction = $CatchActionFunction
            }
            $wowMsRegistryKeyParams = @{
                MachineName         = $MachineName
                SubKey              = $wowMsRegistryKey
                CatchActionFunction = $CatchActionFunction
            }
            Get-RemoteRegistryValue @msRegistryKeyParams -GetValue "SystemDefaultTlsVersions" |
                Invoke-RemotePipelineHandler -Result ([ref]$systemDefaultTlsVersionsValue)
            Get-RemoteRegistryValue  @msRegistryKeyParams -GetValue "SchUseStrongCrypto" |
                Invoke-RemotePipelineHandler -Result ([ref]$schUseStrongCryptoValue)
            Get-RemoteRegistryValue @wowMsRegistryKeyParams -GetValue "SystemDefaultTlsVersions" |
                Invoke-RemotePipelineHandler -Result ([ref]$wowSystemDefaultTlsVersionsValue)
            Get-RemoteRegistryValue @wowMsRegistryKeyParams -GetValue "SchUseStrongCrypto" |
                Invoke-RemotePipelineHandler -Result ([ref]$wowSchUseStrongCryptoValue)

            Get-NETDefaultTLSValue -KeyValue $SystemDefaultTlsVersionsValue -NetVersion $netVersion -KeyName "SystemDefaultTlsVersions" |
                Invoke-RemotePipelineHandler -Result ([ref]$systemDefaultTlsVersions)
            Get-NETDefaultTLSValue -KeyValue $wowSystemDefaultTlsVersionsValue -NetVersion $netVersion -KeyName "WowSystemDefaultTlsVersions" |
                Invoke-RemotePipelineHandler -Result ([ref]$wowSystemDefaultTlsVersions)
            Get-NETDefaultTLSValue -KeyValue $schUseStrongCryptoValue -NetVersion $netVersion -KeyName "SchUseStrongCrypto" |
                Invoke-RemotePipelineHandler -Result ([ref]$schUseStrongCrypto)
            Get-NETDefaultTLSValue -KeyValue $wowSchUseStrongCryptoValue -NetVersion $netVersion -KeyName "WowSchUseStrongCrypto" |
                Invoke-RemotePipelineHandler -Result ([ref]$wowSchUseStrongCrypto)

            $currentNetTlsDefaultVersionObject = [PSCustomObject]@{
                NetVersion                       = $netVersion
                SystemDefaultTlsVersions         = $systemDefaultTlsVersions
                SystemDefaultTlsVersionsValue    = $systemDefaultTlsVersionsValue
                SchUseStrongCrypto               = $schUseStrongCrypto
                SchUseStrongCryptoValue          = $schUseStrongCryptoValue
                MicrosoftRegistryLocation        = $msRegistryKey
                WowSystemDefaultTlsVersions      = $wowSystemDefaultTlsVersions
                WowSystemDefaultTlsVersionsValue = $wowSystemDefaultTlsVersionsValue
                WowSchUseStrongCrypto            = $wowSchUseStrongCrypto
                WowSchUseStrongCryptoValue       = $wowSchUseStrongCryptoValue
                WowRegistryLocation              = $wowMsRegistryKey
                SDtvConfiguredCorrectly          = $systemDefaultTlsVersions -eq $wowSystemDefaultTlsVersions
                SDtvEnabled                      = $systemDefaultTlsVersions -and $wowSystemDefaultTlsVersions
            }

            $hashKeyName = "NET{0}" -f ($netVersion.Split(".")[0])
            $allTlsObjects.NET.Add($hashKeyName, $currentNetTlsDefaultVersionObject)
        }
        return $allTlsObjects
    }
}
