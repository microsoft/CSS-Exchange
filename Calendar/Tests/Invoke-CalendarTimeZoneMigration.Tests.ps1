# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

BeforeAll {
    $Script:parentPath = Split-Path -Parent $PSScriptRoot
    # Get-Command reads the parameter metadata without running the script.
    $Script:command = Get-Command -Name (Join-Path -Path $Script:parentPath -ChildPath 'Invoke-CalendarTimeZoneMigration.ps1')
}

Describe 'Testing Invoke-CalendarTimeZoneMigration.ps1 parameters' {
    It 'Does not require -EwsUrl in any parameter set' {
        $parameter = $Script:command.Parameters['EwsUrl']
        $parameter | Should -Not -BeNullOrEmpty
        @($parameter.ParameterSets.Values | Where-Object { $_.IsMandatory }) | Should -HaveCount 0
    }

    It 'Makes -Mailbox optional for listing time zones' {
        $Script:command.Parameters['Mailbox'].ParameterSets['ListTimeZones'].IsMandatory | Should -BeFalse
    }

    It 'Requires -Mailbox in the <_> parameter set' -ForEach @('Report', 'MigrateSearch') {
        $Script:command.Parameters['Mailbox'].ParameterSets[$_].IsMandatory | Should -BeTrue
    }

    It 'Accepts -Mailbox only in the report, search and list sets' {
        @($Script:command.Parameters['Mailbox'].ParameterSets.Keys | Sort-Object) -join ',' | Should -BeExactly 'ListTimeZones,MigrateSearch,Report'
    }
}
