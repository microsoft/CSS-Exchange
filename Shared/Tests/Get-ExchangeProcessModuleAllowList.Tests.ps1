# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()
BeforeAll {
    $parent = Split-Path -Parent $PSScriptRoot
    . "$parent\Get-ExchangeProcessModuleAllowList.ps1"
    $allowList = Get-ExchangeProcessModuleAllowList
}

Describe "Get-ExchangeProcessModuleAllowList" {
    It "Returns non-empty string arrays" {
        $allowList.ModuleNames.GetType().Name | Should -Be "String[]"
        $allowList.CompanyNames.GetType().Name | Should -Be "String[]"
        $allowList.FipFsCompanyNames.GetType().Name | Should -Be "String[]"
        $allowList.AmsiKnownModuleNames.GetType().Name | Should -Be "String[]"
        $allowList.ModuleNames.Count | Should -BeGreaterThan 0
        $allowList.CompanyNames.Count | Should -BeGreaterThan 0
        $allowList.FipFsCompanyNames.Count | Should -BeGreaterThan 0
    }

    It "Has no duplicate entries" {
        ($allowList.ModuleNames | Sort-Object -Unique).Count | Should -Be $allowList.ModuleNames.Count
        ($allowList.CompanyNames | Sort-Object -Unique).Count | Should -Be $allowList.CompanyNames.Count
    }

    It "Contains IL module names only" {
        $allowList.ModuleNames | Where-Object { $_ -like "*.ni.dll" } | Should -BeNullOrEmpty
    }

    It "Contains modules shipped with Exchange that have no or a non-Microsoft company name" {
        $allowList.ModuleNames | Should -Contain "ManagedBlingSigned.dll"
        $allowList.ModuleNames | Should -Contain "Google.Protobuf.dll"
    }

    It "Contains localized Microsoft company names" {
        $allowList.CompanyNames | Should -Contain "Microsoft Corporation"
        $allowList.CompanyNames | Where-Object { $_ -notlike "*Microsoft*" } | Should -Not -BeNullOrEmpty
    }
}
