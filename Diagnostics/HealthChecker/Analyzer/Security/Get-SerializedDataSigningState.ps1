# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Get-FilteredSettingOverrideInformation.ps1
. $PSScriptRoot\..\..\..\..\Shared\CompareExchangeBuildLevel.ps1
# Used to determine the state of the Serialized Data Signing on the server.
function Get-SerializedDataSigningState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "HealthServerObject")]
        [object]$HealthServerObject,

        [Parameter(Mandatory = $true, ParameterSetName = "SecurityObject")]
        [object]$SecurityObject
    )
    begin {
        <#
        SerializedDataSigning was introduced with the January 2023 Exchange Server Security Update
        In the first release of the feature, it was disabled by default.
        After November 2023 Exchange Server Security Update, it was enabled by default.

        Jan23SU thru Nov23SU
        - Exchange 2016/2019 > Feature must be enabled via New-SettingOverride
        - Exchange 2013 > Feature must be enabled via EnableSerializationDataSigning registry value

        Nov23SU +
        - Exchange 2016/2019 > Feature is enabled by default, but can be disabled by New-SettingOverride.

        Note:
        If the registry value is set on E16/E19, it will be ignored.
        Same goes for the SettingOverride set on E15 - it will be ignored and the feature remains off until the registry value is set.
        #>
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Write-Verbose "ParameterSetName: $($PSCmdlet.ParameterSetName)"

        if ($PSCmdlet.ParameterSetName -eq "HealthServerObject") {
            $exchangeInformation = $HealthServerObject.ExchangeInformation
            $getSettingOverride = $HealthServerObject.OrganizationInformation.GetSettingOverride
        } else {
            $exchangeInformation = $SecurityObject.ExchangeInformation
            $getSettingOverride = $SecurityObject.OrgInformation.GetSettingOverride
        }

        $additionalInformation = [string]::Empty
        $serializedDataSigningEnabled = $false
        $supportedRole = $exchangeInformation.GetExchangeServer.IsEdgeServer -eq $false
        $supportedVersion = (Test-ExchangeBuildGreaterOrEqualThanSecurityPatch -CurrentExchangeBuild $exchangeInformation.BuildInformation.VersionInformation -SUName "Jan23SU")
        $enabledByDefaultVersion = (Test-ExchangeBuildGreaterOrEqualThanSecurityPatch -CurrentExchangeBuild $exchangeInformation.BuildInformation.VersionInformation -SUName "Nov23SU")
        $filterServer = $exchangeInformation.GetExchangeServer.Name
        $exchangeBuild = $exchangeInformation.BuildInformation.VersionInformation.BuildVersion
        Write-Verbose "Reviewing settings against build: $exchangeBuild"
    } process {

        if ($supportedVersion -and
            $supportedRole) {
            Write-Verbose "SerializedDataSigning is available on this Exchange role / version build combination"

            if ($exchangeBuild -ge "15.1.0.0") {
                Write-Verbose "Checking SettingOverride for SerializedDataSigning configuration state"
                $params = @{
                    ExchangeSettingOverride = $exchangeInformation.SettingOverrides
                    GetSettingOverride      = $getSettingOverride
                    FilterServer            = $filterServer
                    FilterServerVersion     = $exchangeBuild
                    FilterComponentName     = "Data"
                    FilterSectionName       = "EnableSerializationDataSigning"
                    FilterParameterName     = "Enabled"
                }

                [array]$serializedDataSigningSettingOverride = Get-FilteredSettingOverrideInformation @params

                if ($null -eq $serializedDataSigningSettingOverride) {
                    Write-Verbose "No Setting Override Found"
                    $serializedDataSigningEnabled = $enabledByDefaultVersion
                } elseif ($serializedDataSigningSettingOverride.Count -eq 1) {
                    $stateValue = $serializedDataSigningSettingOverride.ParameterValue

                    if ($stateValue -eq "False") {
                        $additionalInformation = "SerializedDataSigning is explicitly disabled"
                        Write-Verbose $additionalInformation
                    } elseif ($stateValue -eq "True") {
                        Write-Verbose "SerializedDataSigning is explicitly enabled"
                        $serializedDataSigningEnabled = $true
                    } else {
                        Write-Verbose "Unknown value provided"
                        $additionalInformation = "SerializedDataSigning is unknown"
                    }
                } else {
                    Write-Verbose "Multi overrides detected"
                    $additionalInformation = "SerializedDataSigning is unknown - Multi Setting Overrides Applied: $([string]::Join(", ", $serializedDataSigningSettingOverride.Name))"
                }
            } else {
                Write-Verbose "Checking Registry Value for SerializedDataSigning configuration state"

                if ($exchangeInformation.RegistryValues.SerializedDataSigning -eq 1) {
                    $serializedDataSigningEnabled = $true
                    Write-Verbose "SerializedDataSigning enabled via Registry Value"
                } else {
                    Write-Verbose "SerializedDataSigning not configured or explicitly disabled via Registry Value"
                }
            }
        } else {
            Write-Verbose "SerializedDataSigning isn't available because we are on role: $($exchangeInformation.BuildInformation.ServerRole) build: $exchangeBuild"
        }
    } end {
        return [PSCustomObject]@{
            Enabled                 = $serializedDataSigningEnabled
            SupportedVersion        = $supportedVersion
            SupportedRole           = $supportedRole
            EnabledByDefaultVersion = $enabledByDefaultVersion
            AdditionalInformation   = $additionalInformation
        }
    }
}
