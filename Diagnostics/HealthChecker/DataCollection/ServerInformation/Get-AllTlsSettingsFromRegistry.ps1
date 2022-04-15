# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Get-RemoteRegistryValue.ps1
Function Get-AllTlsSettingsFromRegistry {
    [CmdletBinding()]
    param(
        [string]$MachineName = $env:COMPUTERNAME,
        [scriptblock]$CatchActionFunction
    )
    begin {

        Function Get-TLSMemberValue {
            param(
                [Parameter(Mandatory = $true)]
                [string]
                $GetKeyType,

                [Parameter(Mandatory = $false)]
                [object]
                $KeyValue
            )
            Write-Verbose "KeyValue is null: '$($null -eq $KeyValue)' | KeyValue: '$KeyValue' | GetKeyType: $GetKeyType"
            switch ($GetKeyType) {
                "Enabled" {
                    return $null -eq $KeyValue -or $KeyValue -eq 1
                }
                "DisabledByDefault" {
                    return $null -ne $KeyValue -and $KeyValue -eq 1
                }
            }
        }

        Function Get-NETDefaultTLSValue {
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
        $tlsVersions = @("1.0", "1.1", "1.2")
        $enabledKey = "Enabled"
        $disabledKey = "DisabledByDefault"
        $netVersions = @("v2.0.50727", "v4.0.30319")
        $netRegistryBase = "SOFTWARE\{0}\.NETFramework\{1}"
        $allTlsObjects = [PSCustomObject]@{
            "TLS" = @{}
            "NET" = @{}
        }
    }
    process {
        foreach ($tlsVersion in $tlsVersions) {
            $registryServer = $registryBase -f $tlsVersion, "Server"
            $registryClient = $registryBase -f $tlsVersion, "Client"

            # Get the Enabled and DisabledByDefault values
            $serverEnabledValue = Get-RemoteRegistryValue `
                -MachineName $MachineName `
                -SubKey $registryServer `
                -GetValue $enabledKey `
                -CatchActionFunction $CatchActionFunction
            $serverDisabledByDefaultValue = Get-RemoteRegistryValue `
                -MachineName $MachineName `
                -SubKey $registryServer `
                -GetValue $disabledKey `
                -CatchActionFunction $CatchActionFunction
            $clientEnabledValue = Get-RemoteRegistryValue `
                -MachineName $MachineName `
                -SubKey $registryClient `
                -GetValue $enabledKey `
                -CatchActionFunction $CatchActionFunction
            $clientDisabledByDefaultValue = Get-RemoteRegistryValue `
                -MachineName $MachineName `
                -SubKey $registryClient `
                -GetValue $disabledKey `
                -CatchActionFunction $CatchActionFunction

            $serverEnabled = (Get-TLSMemberValue -GetKeyType $enabledKey -KeyValue $serverEnabledValue)
            $serverDisabledByDefault = (Get-TLSMemberValue -GetKeyType $disabledKey -KeyValue $serverDisabledByDefaultValue)
            $clientEnabled = (Get-TLSMemberValue -GetKeyType $enabledKey -KeyValue $clientEnabledValue)
            $clientDisabledByDefault = (Get-TLSMemberValue -GetKeyType $disabledKey -KeyValue $clientDisabledByDefaultValue)
            $disabled = $serverEnabled -eq $false -and $serverDisabledByDefault -and $clientEnabled -eq $false -and $clientDisabledByDefault
            $misconfigured = $serverEnabled -ne $clientEnabled -or $serverDisabledByDefault -ne $clientDisabledByDefault
            # only need to test server settings here, because $misconfigured will be set and will be the official status.
            # want to check for if Server is Disabled and Disabled By Default is not set or the reverse. This would be only part disabled
            # and not what we recommend on the blog post.
            $halfDisabled = ($serverEnabled -eq $false -and $serverDisabledByDefault -eq $false) -or ($serverEnabled -and $serverDisabledByDefault)
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
                "Client$enabledKey"        = $clientEnabled
                "Client$enabledKey`Value"  = $clientEnabledValue
                "Client$disabledKey"       = $clientDisabledByDefault
                "Client$disabledKey`Value" = $clientDisabledByDefaultValue
                "TLSVersionDisabled"       = $disabled
                "TLSMisconfigured"         = $misconfigured
                "TLSHalfDisabled"          = $halfDisabled
                "TLSConfiguration"         = $configuration
            }
            $allTlsObjects.TLS.Add($TlsVersion, $currentTLSObject)
        }

        foreach ($netVersion in $netVersions) {

            $systemDefaultTlsVersionsValue = Get-RemoteRegistryValue `
                -MachineName $MachineName `
                -SubKey ($netRegistryBase -f "Microsoft", $netVersion) `
                -GetValue "SystemDefaultTlsVersions" `
                -CatchActionFunction $CatchActionFunction
            $schUseStrongCryptoValue = Get-RemoteRegistryValue `
                -MachineName $MachineName `
                -SubKey ($netRegistryBase -f "Microsoft", $netVersion) `
                -GetValue "SchUseStrongCrypto" `
                -CatchActionFunction $CatchActionFunction
            $wowSystemDefaultTlsVersionsValue = Get-RemoteRegistryValue `
                -MachineName $MachineName `
                -SubKey ($netRegistryBase -f "Wow6432Node\Microsoft", $netVersion) `
                -GetValue "SystemDefaultTlsVersions" `
                -CatchActionFunction $CatchActionFunction
            $wowSchUseStrongCryptoValue = Get-RemoteRegistryValue `
                -MachineName $MachineName `
                -SubKey ($netRegistryBase -f "Wow6432Node\Microsoft", $netVersion) `
                -GetValue "SchUseStrongCrypto" `
                -CatchActionFunction $CatchActionFunction

            $systemDefaultTlsVersions = (Get-NETDefaultTLSValue -KeyValue $SystemDefaultTlsVersionsValue -NetVersion $netVersion -KeyName "SystemDefaultTlsVersions")
            $wowSystemDefaultTlsVersions = (Get-NETDefaultTLSValue -KeyValue $wowSystemDefaultTlsVersionsValue -NetVersion $netVersion -KeyName "WowSystemDefaultTlsVersions")

            $currentNetTlsDefaultVersionObject = [PSCustomObject]@{
                NetVersion                       = $netVersion
                SystemDefaultTlsVersions         = $systemDefaultTlsVersions
                SystemDefaultTlsVersionsValue    = $systemDefaultTlsVersionsValue
                SchUseStrongCrypto               = (Get-NETDefaultTLSValue -KeyValue $schUseStrongCryptoValue -NetVersion $netVersion -KeyName "SchUseStrongCrypto")
                WowSystemDefaultTlsVersions      = $wowSystemDefaultTlsVersions
                WowSystemDefaultTlsVersionsValue = $wowSystemDefaultTlsVersionsValue
                WowSchUseStrongCrypto            = (Get-NETDefaultTLSValue -KeyValue $wowSchUseStrongCryptoValue -NetVersion $netVersion -KeyName "WowSchUseStrongCrypto")
                SdtvConfiguredCorrectly          = $systemDefaultTlsVersions -eq $wowSystemDefaultTlsVersions
                SdtvEnabled                      = $systemDefaultTlsVersions -and $wowSystemDefaultTlsVersions
            }

            $hashKeyName = "NET{0}" -f ($netVersion.Split(".")[0])
            $allTlsObjects.NET.Add($hashKeyName, $currentNetTlsDefaultVersionObject)
        }
        return $allTlsObjects
    }
}
