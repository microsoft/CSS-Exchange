# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

BeforeAll {
    $Script:collectorRoot = Split-Path -Path $PSScriptRoot -Parent
    $Script:collectorAst = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path -Path $Script:collectorRoot -ChildPath 'ExchangeLogCollector.ps1'),
        [ref]$null,
        [ref]$null)

    . $Script:collectorRoot\Helpers\Get-ArgumentList.ps1
    . $Script:collectorRoot\Helpers\Test-NoSwitchesProvided.ps1
    . $Script:collectorRoot\Helpers\Test-PossibleCommonScenarios.ps1
    . $Script:collectorRoot\RemoteScriptBlock\Invoke-RemoteMain.ps1
}

Describe 'MRSProxy log selection' {
    BeforeEach {
        foreach ($parameter in $Script:collectorAst.ParamBlock.Parameters) {
            Set-Variable -Name $parameter.Name.VariablePath.UserPath -Value $null -Scope Script
        }

        $Script:MRSProxyLogs = $false
        $Script:AnyTransportSwitchesEnabled = $false
        $Script:CollectAllLogsBasedOnLogAge = $true
        $Script:LogAge = [TimeSpan]::FromDays(3)
        $Script:LogEndAge = [TimeSpan]::Zero
        $Script:StandardFreeSpaceInGBCheckSize = 10
        $Script:RootFilePath = Join-Path -Path $TestDrive -ChildPath 'Collected'
        $Script:RootCopyToDirectory = Join-Path -Path $Script:RootFilePath -ChildPath $env:COMPUTERNAME
        $Script:exchangeInstallPath = (Join-Path -Path $TestDrive -ChildPath 'Exchange') + '\'
        $Script:serverObject = [PSCustomObject]@{
            ServerName = $env:COMPUTERNAME
            Version    = 19
            Mailbox    = $true
            CAS        = $true
            Edge       = $false
            DAGMember  = $false
        }

        Mock Get-ServerObjects { return $Script:serverObject }
        Mock Get-ExchangeInstallDirectory { return $Script:exchangeInstallPath }
        Mock Get-IISLogDirectory {
            Join-Path -Path $TestDrive -ChildPath 'IIS\W3SVC1'
            Join-Path -Path $TestDrive -ChildPath 'IIS\W3SVC2'
        }
        Mock Get-FreeSpace { return 100 }
        Mock Invoke-ErrorMonitoring {}
        Mock Copy-LogsBasedOnTime {}
        Mock Copy-FullLogFullPathRecurse {}
        Mock Save-WindowsEventLogs {}
        Mock Save-DataInfoToFile {}
        Mock Get-UnhandledErrors {}
        Mock Get-HandledErrors {}
        Mock Enter-YesNoLoopAction {}
    }

    It 'exposes the MRSProxyLogs switch' {
        $parameter = $Script:collectorAst.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'MRSProxyLogs' }
        $parameter.StaticType | Should -Be ([System.Management.Automation.SwitchParameter])
    }

    It 'passes the selected switch through serialized remote arguments' {
        $Script:MRSProxyLogs = $true
        $arguments = Get-ArgumentList -Servers @($env:COMPUTERNAME)
        $serialized = [System.Management.Automation.PSSerializer]::Serialize($arguments)
        $remoteArguments = [System.Management.Automation.PSSerializer]::Deserialize($serialized)

        $remoteArguments.MRSProxyLogs | Should -BeTrue
    }

    It 'includes MRSProxy logs in AllPossibleLogs' {
        $Script:AllPossibleLogs = $true

        Test-PossibleCommonScenarios

        $Script:MRSProxyLogs | Should -BeTrue
    }

    It 'accepts MRSProxyLogs as the only selected log category' {
        $Script:MRSProxyLogs = $true

        Test-NoSwitchesProvided

        Should -Invoke -CommandName Enter-YesNoLoopAction -Times 0 -Exactly
    }

    It 'enables EWS and IIS and forwards the selection to remote servers' {
        $Script:MRSProxyLogs = $true

        Test-PossibleCommonScenarios

        $arguments = Get-ArgumentList -Servers @($env:COMPUTERNAME)
        $remoteArguments = [System.Management.Automation.PSSerializer]::Deserialize(
            [System.Management.Automation.PSSerializer]::Serialize($arguments))

        $remoteArguments.MRSProxyLogs | Should -BeTrue
        $remoteArguments.EWSLogs | Should -BeTrue
        $remoteArguments.IISLogs | Should -BeTrue
    }

    It 'does not enable EWS or IIS when MRSProxyLogs is not selected' {
        Test-PossibleCommonScenarios

        [bool]$Script:EWSLogs | Should -BeFalse
        [bool]$Script:IISLogs | Should -BeFalse
    }

    It 'preserves individually selected EWS and IIS logs' {
        $Script:EWSLogs = $true
        $Script:IISLogs = $true

        Test-PossibleCommonScenarios

        $Script:EWSLogs | Should -BeTrue
        $Script:IISLogs | Should -BeTrue
        $Script:MRSProxyLogs | Should -BeFalse
    }

    It 'collects MRS, EWS, IIS and HTTP error logs with only MRSProxyLogs selected' {
        $Script:MRSProxyLogs = $true
        Test-PossibleCommonScenarios
        $Script:PassedInfo = Get-ArgumentList -Servers @($env:COMPUTERNAME)

        Invoke-RemoteMain

        Should -Invoke -CommandName Copy-LogsBasedOnTime -Times 7 -Exactly
        Should -Invoke -CommandName Copy-LogsBasedOnTime -Times 1 -Exactly -ParameterFilter {
            $LogPath -eq ($Script:exchangeInstallPath + 'Logging\EWS')
        }
        Should -Invoke -CommandName Copy-LogsBasedOnTime -Times 1 -Exactly -ParameterFilter {
            $LogPath -eq ($Script:exchangeInstallPath + 'Logging\HttpProxy\Ews')
        }
        Should -Invoke -CommandName Copy-LogsBasedOnTime -Times 2 -Exactly -ParameterFilter {
            $LogPath -like '*\IIS\W3SVC*'
        }
        Should -Invoke -CommandName Copy-FullLogFullPathRecurse -Times 0 -Exactly
    }

    It 'schedules both default folders recursively using the time filter on version <Version>' -TestCases @(
        @{ Version = 15 }
        @{ Version = 16 }
        @{ Version = 19 }
    ) {
        param($Version)
        $Script:MRSProxyLogs = $true
        $Script:serverObject.Version = $Version
        $Script:PassedInfo = Get-ArgumentList -Servers @($env:COMPUTERNAME)

        Invoke-RemoteMain

        Should -Invoke -CommandName Copy-LogsBasedOnTime -Times 1 -Exactly -ParameterFilter {
            $LogPath -eq ($Script:exchangeInstallPath + 'Logging\MailboxReplicationService') -and
            $CopyToThisLocation -eq (Join-Path -Path $Script:RootCopyToDirectory -ChildPath 'MRS_Logs') -and
            $IncludeSubDirectory
        }
        Should -Invoke -CommandName Copy-LogsBasedOnTime -Times 1 -Exactly -ParameterFilter {
            $LogPath -eq ($Script:exchangeInstallPath + 'Logging\MrsProxyAuthorization') -and
            $CopyToThisLocation -eq (Join-Path -Path $Script:RootCopyToDirectory -ChildPath 'MRS_Proxy_Authorization_Logs') -and
            $IncludeSubDirectory
        }
        Should -Invoke -CommandName Copy-FullLogFullPathRecurse -Times 0 -Exactly
    }

    It 'uses full-folder collection when the time filter is disabled' {
        $Script:MRSProxyLogs = $true
        $Script:CollectAllLogsBasedOnLogAge = $false
        $Script:PassedInfo = Get-ArgumentList -Servers @($env:COMPUTERNAME)

        Invoke-RemoteMain

        Should -Invoke -CommandName Copy-FullLogFullPathRecurse -Times 1 -Exactly -ParameterFilter {
            $LogPath -eq ($Script:exchangeInstallPath + 'Logging\MailboxReplicationService')
        }
        Should -Invoke -CommandName Copy-FullLogFullPathRecurse -Times 1 -Exactly -ParameterFilter {
            $LogPath -eq ($Script:exchangeInstallPath + 'Logging\MrsProxyAuthorization')
        }
        Should -Invoke -CommandName Copy-LogsBasedOnTime -Times 0 -Exactly
    }

    It 'does not collect these folders unless selected' {
        $Script:PassedInfo = Get-ArgumentList -Servers @($env:COMPUTERNAME)

        Invoke-RemoteMain

        Should -Invoke -CommandName Copy-LogsBasedOnTime -Times 0 -Exactly
        Should -Invoke -CommandName Copy-FullLogFullPathRecurse -Times 0 -Exactly
    }

    It 'does not collect MRSProxy folders on CAS-only or Edge roles' {
        $Script:MRSProxyLogs = $true
        $Script:serverObject.Mailbox = $false
        $Script:PassedInfo = Get-ArgumentList -Servers @($env:COMPUTERNAME)

        Invoke-RemoteMain

        Should -Invoke -CommandName Copy-LogsBasedOnTime -Times 0 -Exactly
        Should -Invoke -CommandName Copy-FullLogFullPathRecurse -Times 0 -Exactly
    }
}
