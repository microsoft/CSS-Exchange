# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()
BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    $Script:Server = $env:COMPUTERNAME
    . $Script:parentPath\New-AuthCertificateMonitoringLogFolder.ps1
}

Describe "Testing New-AuthCertificateMonitoringLogFolder.ps1" {

    Context "Executed On Exchange Server" {
        BeforeAll {
            $env:ExchangeInstallPath = 'C:\Program Files\Microsoft\Exchange Server\V15'
            $Script:results = New-AuthCertificateMonitoringLogFolder
        }

        It "Should Create The Log Folder Under ExchangeInstallPath" {
            $results | Should -Be 'C:\Program Files\Microsoft\Exchange Server\V15\Logging\AuthCertificateMonitoring'
        }
    }

    Context "Executed On Non-Exchange Server" {
        BeforeAll {
            $env:ExchangeInstallPath = $null
            $Script:results = New-AuthCertificateMonitoringLogFolder
        }

        It "Should Create The Log Folder Under Temp Folder" {
            $results | Should -Be ('{0}\Logging\AuthCertificateMonitoring' -f $env:TEMP)
        }
    }
}
