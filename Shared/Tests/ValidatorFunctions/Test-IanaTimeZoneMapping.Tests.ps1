# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

BeforeAll {
    $parent = Split-Path -Parent $PSScriptRoot
    $scriptName = "Test-IanaTimeZoneMapping.ps1"

    . "$parent\..\ValidatorFunctions\$scriptName"

    $script:brokenIanaTimeZoneMappingsPath = "$parent\ValidatorFunctions\Data\IanaTimeZoneMappings_broken.xml"
    $script:workingIanaTimeZoneMappingsPath = "$parent\ValidatorFunctions\Data\IanaTimeZoneMappings.xml"

    [xml]$script:brokenIanaTimeZoneMappingsXml = Get-Content $brokenIanaTimeZoneMappingsPath -Raw -Encoding UTF8
    [xml]$script:workingIanaTimeZoneMappingsXml = Get-Content $workingIanaTimeZoneMappingsPath -Raw -Encoding UTF8
}

Describe "Testing Test-IanaTimeZoneMapping" {

    Context "Test with broken IanaTimeZoneMappings.xml via FilePath" {

        It "Should find 2 duplicate entries" {
            $results = Test-IanaTimeZoneMapping -FilePath $brokenIanaTimeZoneMappingsPath
            $results.DuplicateEntries | Should -HaveCount 2
        }

        It "Should return duplicates as PSCustomObject" {
            $results = Test-IanaTimeZoneMapping -FilePath $brokenIanaTimeZoneMappingsPath
            foreach ($entry in $results.DuplicateEntries) {
                $entry | Should -BeOfType PSCustomObject
            }
        }

        It "Should find 2 nodes missing attributes" {
            $results = Test-IanaTimeZoneMapping -FilePath $brokenIanaTimeZoneMappingsPath
            $results.NodeMissingAttributes | Should -HaveCount 2
        }
    }

    Context "Test with working IanaTimeZoneMappings.xml via FilePath" {

        It "Should not find duplicate entries" {
            $results = Test-IanaTimeZoneMapping -FilePath $workingIanaTimeZoneMappingsPath
            $results.DuplicateEntries | Should -HaveCount 0
        }

        It "Should not find nodes missing attributes" {
            $results = Test-IanaTimeZoneMapping -FilePath $workingIanaTimeZoneMappingsPath
            $results.NodeMissingAttributes | Should -HaveCount 0
        }
    }

    Context "Test with IanaMappingFile parameter" {

        It "Should find 2 duplicate entries" {
            $results = Test-IanaTimeZoneMapping -IanaMappingFile $brokenIanaTimeZoneMappingsXml
            $results.DuplicateEntries | Should -HaveCount 2
        }

        It "Should find 2 nodes missing attributes" {
            $results = Test-IanaTimeZoneMapping -IanaMappingFile $brokenIanaTimeZoneMappingsXml
            $results.NodeMissingAttributes | Should -HaveCount 2
        }

        It "Should not find duplicate entries" {
            $results = Test-IanaTimeZoneMapping -IanaMappingFile $workingIanaTimeZoneMappingsXml
            $results.DuplicateEntries | Should -HaveCount 0
        }

        It "Should not find nodes missing attributes" {
            $results = Test-IanaTimeZoneMapping -IanaMappingFile $workingIanaTimeZoneMappingsXml
            $results.NodeMissingAttributes | Should -HaveCount 0
        }
    }
}
