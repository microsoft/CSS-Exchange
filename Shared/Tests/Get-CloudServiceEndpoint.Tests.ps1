# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

BeforeAll {
    $Script:parentPath = Split-Path -Path $PSScriptRoot -Parent
    $Script:scriptName = "Get-CloudServiceEndpoint.ps1"

    . "$Script:parentPath\AzureFunctions\$Script:scriptName"

    # Every environment the function is expected to resolve, and the properties it must return.
    $Script:expectedProperties = @(
        "EnvironmentName"
        "GraphApiEndpoint"
        "ExchangeOnlineEndpoint"
        "AutoDiscoverSecureName"
        "AzureADEndpoint"
    )
}

Describe "Testing Get-CloudServiceEndpoint.ps1" {

    Context "Resolving a known environment" {

        It "Returns every endpoint for <EndpointName>" -TestCases @(
            @{ EndpointName = "Global"; EnvironmentName = "AzureCloud" }
            @{ EndpointName = "USGovernmentL4"; EnvironmentName = "AzureUSGovernment" }
            @{ EndpointName = "USGovernmentL5"; EnvironmentName = "AzureUSGovernment" }
            @{ EndpointName = "ChinaCloud"; EnvironmentName = "AzureChinaCloud" }
            @{ EndpointName = "BleuCloud"; EnvironmentName = "BleuCloud" }
            @{ EndpointName = "DelosCloud"; EnvironmentName = "DelosCloud" }
        ) {
            param($EndpointName, $EnvironmentName)

            $result = Get-CloudServiceEndpoint -EndpointName $EndpointName

            $result.EnvironmentName | Should -BeExactly $EnvironmentName
            foreach ($property in $Script:expectedProperties) {
                $result.$property | Should -Not -BeNullOrEmpty -Because "$property must be populated for $EndpointName"
            }
        }

        It "Returns https endpoints only for <EndpointName>" -TestCases @(
            @{ EndpointName = "Global" }
            @{ EndpointName = "USGovernmentL4" }
            @{ EndpointName = "USGovernmentL5" }
            @{ EndpointName = "ChinaCloud" }
            @{ EndpointName = "BleuCloud" }
            @{ EndpointName = "DelosCloud" }
        ) {
            param($EndpointName)

            $result = Get-CloudServiceEndpoint -EndpointName $EndpointName

            foreach ($property in @("GraphApiEndpoint", "ExchangeOnlineEndpoint", "AutoDiscoverSecureName", "AzureADEndpoint")) {
                $result.$property | Should -BeLike "https://*" -Because "$property must not be reachable over plain http"
            }
        }

        It "Does not hand the same endpoints to two different environments" {
            $allEndpoints = @("Global", "USGovernmentL4", "USGovernmentL5", "ChinaCloud", "BleuCloud", "DelosCloud") |
                ForEach-Object { (Get-CloudServiceEndpoint -EndpointName $_).GraphApiEndpoint }

            ($allEndpoints | Select-Object -Unique).Count | Should -Be $allEndpoints.Count
        }
    }

    Context "Rejecting an unusable environment" {

        It "Throws instead of returning null endpoints for <Reason>" -TestCases @(
            @{ Reason = "an unknown name"; EndpointName = "NotACloud" }
            @{ Reason = "a trailing space"; EndpointName = "USGovernmentL4 " }
            @{ Reason = "an empty string"; EndpointName = "" }
            @{ Reason = "a null value"; EndpointName = $null }
        ) {
            param($Reason, $EndpointName)

            { Get-CloudServiceEndpoint -EndpointName $EndpointName } | Should -Throw
        }

        It "Requires the environment to be supplied" {
            # A missing value previously produced an object whose properties were all null.
            (Get-Command -Name Get-CloudServiceEndpoint).Parameters["EndpointName"].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                Select-Object -ExpandProperty Mandatory |
                Should -Contain $true
        }
    }

    Context "Keeping the validation and the lookup in step" {

        It "Defines endpoints for every value the parameter accepts" {
            $validValues = (Get-Command -Name Get-CloudServiceEndpoint).Parameters["EndpointName"].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
                Select-Object -ExpandProperty ValidValues

            $validValues | Should -Not -BeNullOrEmpty

            foreach ($value in $validValues) {
                { Get-CloudServiceEndpoint -EndpointName $value } | Should -Not -Throw -Because "$value is accepted by the parameter"
            }
        }
    }
}
