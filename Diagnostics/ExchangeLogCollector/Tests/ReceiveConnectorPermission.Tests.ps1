# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

BeforeAll {
    $Script:collectorRoot = Split-Path -Path $PSScriptRoot -Parent
    . $Script:collectorRoot\ExchangeServerInfo\Get-ReceiveConnectorPermission.ps1

    # Exchange cmdlet isn't available in the test environment. Needs to exist to be mocked.
    function Get-ADPermission {
        [CmdletBinding()]
        param(
            [object]$Identity
        )
        throw "no mock detected"
    }

    function Get-TestReceiveConnector {
        param(
            [string]$Name,
            [string]$DistinguishedName = "CN=$Name,CN=SMTP Receive Connectors,CN=Protocols,CN=EXCH1,CN=Servers,DC=contoso,DC=com"
        )
        return [PSCustomObject]@{
            Identity          = "EXCH1\$Name"
            DistinguishedName = $DistinguishedName
        }
    }

    # Simulates a deserialized Exchange object that is only meaningful through ToString().
    function Get-TestObjectWithToString {
        param(
            [string]$Value
        )
        $testObject = [PSCustomObject]@{ RawIdentity = $Value; ObjectGuid = [guid]::NewGuid() }
        $testObject | Add-Member -MemberType ScriptMethod -Name ToString -Value { $this.RawIdentity } -Force
        return $testObject
    }
}

Describe 'Get-ReceiveConnectorPermission' {
    BeforeEach {
        $Script:connectorA = Get-TestReceiveConnector -Name 'Default EXCH1'
        $Script:connectorB = Get-TestReceiveConnector -Name 'Relay, #1 +[Test]' -DistinguishedName 'CN=Relay\, #1 \+[Test],CN=SMTP Receive Connectors,CN=Protocols,CN=EXCH1,CN=Servers,DC=contoso,DC=com'

        Mock Get-ADPermission {
            [PSCustomObject]@{ Identity = $Identity; User = 'NT AUTHORITY\ANONYMOUS LOGON'; ExtendedRights = 'ms-Exch-SMTP-Submit' }
            [PSCustomObject]@{ Identity = $Identity; User = 'CONTOSO\Exchange Servers'; ExtendedRights = 'ms-Exch-SMTP-Accept-Any-Recipient' }
        }
        Mock Invoke-CatchActions {}
        Mock Write-Host {}
    }

    It 'returns every ACE of every connector by distinguished name' {
        $result = @(Get-ReceiveConnectorPermission -ServerName 'EXCH1' -ReceiveConnector @($Script:connectorA, $Script:connectorB))

        $result.Count | Should -Be 4
        Should -Invoke Get-ADPermission -Times 2 -Exactly
        Should -Invoke Get-ADPermission -Times 1 -Exactly -ParameterFilter { $Identity -eq $Script:connectorA.DistinguishedName }
        Should -Invoke Get-ADPermission -Times 1 -Exactly -ParameterFilter { $Identity -eq $Script:connectorB.DistinguishedName }
        Should -Invoke Write-Host -Times 0 -Exactly
    }

    It 'accepts a single connector object' {
        $result = @(Get-ReceiveConnectorPermission -ServerName 'EXCH1' -ReceiveConnector $Script:connectorA)

        $result.Count | Should -Be 2
        Should -Invoke Get-ADPermission -Times 1 -Exactly
    }

    It 'returns the ACE values as strings without the serialized object data' {
        Mock Get-ADPermission {
            [PSCustomObject]@{
                Identity            = Get-TestObjectWithToString 'EXCH1\Default EXCH1'
                User                = Get-TestObjectWithToString 'NT AUTHORITY\ANONYMOUS LOGON'
                Deny                = $false
                IsInherited         = $true
                InheritanceType     = [System.IO.FileShare]::Read
                AccessRights        = @([System.IO.FileAccess]::Read)
                ExtendedRights      = @((Get-TestObjectWithToString 'ms-Exch-SMTP-Accept-Any-Recipient'), (Get-TestObjectWithToString 'ms-Exch-SMTP-Submit'))
                Properties          = $null
                ChildObjectTypes    = $null
                InheritedObjectType = $null
                SerializationData   = 'Large serialized object'
            }
        }

        $result = @(Get-ReceiveConnectorPermission -ServerName 'EXCH1' -ReceiveConnector $Script:connectorA)

        $result.Count | Should -Be 1
        $result[0].PSObject.Properties.Name | Should -Not -Contain 'SerializationData'
        $result[0].Identity | Should -BeOfType [string]
        $result[0].Identity | Should -Be 'EXCH1\Default EXCH1'
        $result[0].User | Should -Be 'NT AUTHORITY\ANONYMOUS LOGON'
        $result[0].Deny | Should -BeFalse
        $result[0].IsInherited | Should -BeTrue
        $result[0].InheritanceType | Should -Be 'Read'
        $result[0].AccessRights | Should -Be @('Read')
        $result[0].ExtendedRights.GetType() | Should -Be ([string[]])
        $result[0].ExtendedRights | Should -Be @('ms-Exch-SMTP-Accept-Any-Recipient', 'ms-Exch-SMTP-Submit')
        $result[0].Properties.Count | Should -Be 0
        $result[0].ChildObjectTypes.Count | Should -Be 0
        $result[0].InheritedObjectType | Should -Be ([string]::Empty)
    }

    It 'returns nothing and does not call Get-ADPermission when there are no connectors' {
        $result = @(Get-ReceiveConnectorPermission -ServerName 'EXCH1' -ReceiveConnector $null)

        $result.Count | Should -Be 0
        Should -Invoke Get-ADPermission -Times 0 -Exactly
        Should -Invoke Write-Host -Times 0 -Exactly
    }

    It 'never calls Get-ADPermission with an empty identity' {
        $noDn = Get-TestReceiveConnector -Name 'NoDn' -DistinguishedName ''

        $result = @(Get-ReceiveConnectorPermission -ServerName 'EXCH1' -ReceiveConnector @($noDn, $Script:connectorA))

        $result.Count | Should -Be 2
        Should -Invoke Get-ADPermission -Times 1 -Exactly
        Should -Invoke Get-ADPermission -Times 0 -Exactly -ParameterFilter { [string]::IsNullOrEmpty($Identity) }
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { $Object -like '*1 of 2 Receive Connectors on EXCH1*' }
    }

    It 'continues with the next connector when one connector fails' {
        Mock Get-ADPermission -ParameterFilter { $Identity -eq $Script:connectorA.DistinguishedName } -MockWith { throw 'Simulated failure' }

        $result = @(Get-ReceiveConnectorPermission -ServerName 'EXCH1' -ReceiveConnector @($Script:connectorA, $Script:connectorB))

        $result.Count | Should -Be 2
        $result[0].Identity | Should -Be $Script:connectorB.DistinguishedName
        Should -Invoke Invoke-CatchActions -Times 1 -Exactly
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { $Object -like '*1 of 2 Receive Connectors on EXCH1*' }
    }

    It 'does not throw when Get-ADPermission is not available in the session' {
        Mock Get-ADPermission { throw [System.Management.Automation.CommandNotFoundException]::new("The term 'Get-ADPermission' is not recognized") }

        { $Script:result = @(Get-ReceiveConnectorPermission -ServerName 'EXCH1' -ReceiveConnector @($Script:connectorA, $Script:connectorB)) } | Should -Not -Throw

        $Script:result.Count | Should -Be 0
        Should -Invoke Invoke-CatchActions -Times 2 -Exactly
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { $Object -like '*2 of 2 Receive Connectors on EXCH1*' }
    }
}
