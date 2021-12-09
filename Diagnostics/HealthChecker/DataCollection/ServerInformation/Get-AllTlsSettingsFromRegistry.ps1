# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Get-RemoteRegistryValue.ps1
. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
Function Get-AllTlsSettingsFromRegistry {
    [CmdletBinding()]
    [OutputType("System.Collections.Hashtable")]
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
                $KeyValue,

                [Parameter(Mandatory = $true)]
                [string]
                $ServerClientType,

                [Parameter(Mandatory = $true)]
                [string]
                $TlsVersion
            )
            Write-Verbose "KeyValue is null: '$($null -eq $KeyValue)' | KeyValue: '$KeyValue' | ServerClientType: $ServerClientType | TLSVersion: $tlsVersion | GetKeyType: $GetKeyType"
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
        $keyValues = ("Enabled", "DisabledByDefault")
        $netVersions = @("v2.0.50727", "v4.0.30319")
        $netRegistryBase = "SOFTWARE\{0}\.NETFramework\{1}"
        [HashTable]$allTlsObjects = @{}
    }
    process {
        foreach ($tlsVersion in $tlsVersions) {
            $registryServer = $registryBase -f $tlsVersion, "Server"
            $registryClient = $registryBase -f $tlsVersion, "Client"
            $currentTLSObject = [PSCustomObject]@{
                TLSVersion = $tlsVersion
            }

            foreach ($getKey in $keyValues) {

                $serverValue = Get-RemoteRegistryValue `
                    -MachineName $MachineName `
                    -SubKey $registryServer `
                    -GetValue $getKey `
                    -CatchActionFunction $CatchActionFunction
                $clientValue = Get-RemoteRegistryValue `
                    -MachineName $MachineName `
                    -SubKey $registryClient `
                    -GetValue $getKey `
                    -CatchActionFunction $CatchActionFunction

                $currentTLSObject | Add-Member -MemberType NoteProperty `
                    -Name "Server$getKey" `
                    -Value (Get-TLSMemberValue -GetKeyType $getKey -KeyValue $serverValue -ServerClientType "Server" -TlsVersion $tlsVersion)
                $currentTLSObject | Add-Member -MemberType NoteProperty `
                    -Name "Server$getKey`Value" `
                    -Value $serverValue
                $currentTLSObject | Add-Member -MemberType NoteProperty `
                    -Name "Client$getKey" `
                    -Value (Get-TLSMemberValue -GetKeyType $getKey -KeyValue $clientValue -ServerClientType "Client" -TlsVersion $tlsVersion)
                $currentTLSObject | Add-Member -MemberType NoteProperty `
                    -Name "Client$getKey`Value" `
                    -Value $clientValue
            }
            $allTlsObjects.Add($TlsVersion, $currentTLSObject)
        }

        foreach ($netVersion in $netVersions) {
            $currentNetTlsDefaultVersionObject = New-Object PSCustomObject
            $currentNetTlsDefaultVersionObject | Add-Member -MemberType NoteProperty -Name "NetVersion" -Value $netVersion

            $SystemDefaultTlsVersions = Get-RemoteRegistryValue `
                -MachineName $MachineName `
                -SubKey ($netRegistryBase -f "Microsoft", $netVersion) `
                -GetValue "SystemDefaultTlsVersions" `
                -CatchActionFunction $CatchActionFunction
            $SchUseStrongCrypto = Get-RemoteRegistryValue `
                -MachineName $MachineName `
                -SubKey ($netRegistryBase -f "Microsoft", $netVersion) `
                -GetValue "SchUseStrongCrypto" `
                -CatchActionFunction $CatchActionFunction
            $WowSystemDefaultTlsVersions = Get-RemoteRegistryValue `
                -MachineName $MachineName `
                -SubKey ($netRegistryBase -f "Wow6432Node\Microsoft", $netVersion) `
                -GetValue "SystemDefaultTlsVersions" `
                -CatchActionFunction $CatchActionFunction
            $WowSchUseStrongCrypto = Get-RemoteRegistryValue `
                -MachineName $MachineName `
                -SubKey ($netRegistryBase -f "Wow6432Node\Microsoft", $netVersion) `
                -GetValue "SchUseStrongCrypto" `
                -CatchActionFunction $CatchActionFunction

            $currentNetTlsDefaultVersionObject = [PSCustomObject]@{
                NetVersion                  = $netVersion
                SystemDefaultTlsVersions    = (Get-NETDefaultTLSValue -KeyValue $SystemDefaultTlsVersions -NetVersion $netVersion -KeyName "SystemDefaultTlsVersions")
                SchUseStrongCrypto          = (Get-NETDefaultTLSValue -KeyValue $SchUseStrongCrypto -NetVersion $netVersion -KeyName "SchUseStrongCrypto")
                WowSystemDefaultTlsVersions = (Get-NETDefaultTLSValue -KeyValue $WowSystemDefaultTlsVersions -NetVersion $netVersion -KeyName "WowSystemDefaultTlsVersions")
                WowSchUseStrongCrypto       = (Get-NETDefaultTLSValue -KeyValue $WowSchUseStrongCrypto -NetVersion $netVersion -KeyName "WowSchUseStrongCrypto")
                SecurityProtocol            = (Invoke-ScriptBlockHandler -ComputerName $MachineName -ScriptBlock { ([System.Net.ServicePointManager]::SecurityProtocol).ToString() } -CatchActionFunction $CatchActionFunction)
            }

            $hashKeyName = "NET{0}" -f ($netVersion.Split(".")[0])
            $allTlsObjects.Add($hashKeyName, $currentNetTlsDefaultVersionObject)
        }
        return $allTlsObjects
    }
}
