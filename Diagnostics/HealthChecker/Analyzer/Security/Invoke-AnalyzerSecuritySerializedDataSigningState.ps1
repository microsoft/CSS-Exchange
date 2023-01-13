# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-AnalyzerSecuritySerializedDataSigningState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ref]$AnalyzeResults,

        [Parameter(Mandatory = $true)]
        [object]$HealthServerObject,

        [Parameter(Mandatory = $true)]
        [object]$DisplayGroupingKey
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $exchangeInformation = $HealthServerObject.ExchangeInformation
    $serverName = ($HealthServerObject.ServerName.Split(".")[0]).ToLower()
    $exchangeBuild = $exchangeInformation.BuildInformation.VersionInformation.BuildVersion
    $exchangeCU = $exchangeInformation.BuildInformation.VersionInformation.CU
    $exchangeMajor = $exchangeInformation.BuildInformation.MajorVersion
    $baseParams = @{
        AnalyzedInformation = $AnalyzeResults
        DisplayGroupingKey  = $DisplayGroupingKey
    }

    <#
        SerializedDataSigning was introduced with the January 2023 Exchange Server Security Update
        By now, it is disabled by default and must be enabled like this:
        - Exchange 2016/2019 > Feature must be enabled via New-SettingOverride
        - Exchange 2013 > Feature must be enabled via EnableSerializationDataSigning registry value

        Note:
        If the registry value is set on E16/E19, it will be ignored.
        Same goes for the SettingOverride set on E15 - it will be ignored and the feature remains off until the registry value is set.
    #>

    if ($exchangeMajor -eq [HealthChecker.ExchangeMajorVersion]::Exchange2019) {
        switch ($exchangeCU) {
            { $_ -eq "CU12" } { $serializedDataSigningSupportedBuild = ($exchangeBuild -ge "15.2.1118.21"); break }
            { $_ -eq "CU11" } { $serializedDataSigningSupportedBuild = ($exchangeBuild -ge "15.2.986.37"); break }
            default { $serializedDataSigningSupportedBuild = $false }
        }
    } elseif ($exchangeMajor -eq [HealthChecker.ExchangeMajorVersion]::Exchange2016) {
        $serializedDataSigningSupportedBuild = ($exchangeBuild -ge "15.1.2507.17")
    } else {
        $serializedDataSigningSupportedBuild = ($exchangeBuild -ge "15.0.1497.45")
    }

    if (($serializedDataSigningSupportedBuild) -and
        ($exchangeInformation.BuildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::Edge)) {
        Write-Verbose "SerializedDataSigning is available on this Exchange role / version build combination"

        $serializedDataSigningInformation = $HealthServerObject.ExchangeInformation.SerializationDataSigningConfiguration
        $serializedDataSigningWriteType = "Yellow"
        $serializedDataSigningConfigurationWarning = "`r`n`t`tThis may pose a security risk to your servers`r`n`t`tMore Information: https://aka.ms/HC-SerializedDataSigning"

        if ($exchangeMajor -ge [HealthChecker.ExchangeMajorVersion]::Exchange2016) {
            Write-Verbose "Checking SettingOverride for SerializedDataSigning configuration state"
            if (($serializedDataSigningInformation.Count -eq 1) -and
                (-not($serializedDataSigningInformation.FailedQuery -eq $true))) {

                if (($serializedDataSigningInformation.Enabled) -and
                    (($serializedDataSigningInformation.OrgWideSetting) -or
                    ($serializedDataSigningInformation.Server.ToLower().Contains($serverName)))) {
                    Write-Verbose "SerializedDataSigning is enabled for the whole organization or the server which is currently processed"
                    $serializedDataSigningWriteType = "Green"
                    $serializedDataSigningState = $serializedDataSigningInformation.Enabled
                } elseif (($serializedDataSigningInformation.Enabled) -and
                    (-not($serializedDataSigningInformation.Server.ToLower().Contains($serverName)))) {
                    Write-Verbose "SerializedDataSigning is enabled but not for the server which is currently processed"
                    $serializedDataSigningState = $false
                } elseif ($serializedDataSigningInformation.Enabled -eq $false) {
                    Write-Verbose "Checking if SerializedDataSigning is explicitly disabled on organizational level"
                    $serializedDataSigningState = $false
                    switch ($serializedDataSigningInformation.OrgWideSetting) {
                        $true { $additionalSerializedDataSigningDisplayValue = "Setting applies to all servers of the organization" }
                        $false {
                            $additionalSerializedDataSigningDisplayValue = "Setting applies to the following server(s) of the organization:"
                            foreach ($server in $serializedDataSigningInformation.Server) {
                                $additionalSerializedDataSigningDisplayValue += "`r`n`t`t{0}" -f $server
                            }
                        }
                    }
                    $additionalSerializedDataSigningDisplayValue += $serializedDataSigningConfigurationWarning
                } else {
                    $additionalSerializedDataSigningDisplayValue = "SerializedDataSigning configuration state is unknown"
                }
            } elseif ($serializedDataSigningInformation.Count -gt 1) {
                $serializedDataSigningState = "Multiple SerializedDataSigning SettingOverrides detected"
                $additionalSerializedDataSigningDisplayValue = "An override on the server level takes precedence over an organization-wide override"

                $i = 0
                foreach ($override in $serializedDataSigningInformation) {
                    $i++
                    $additionalSerializedDataSigningDisplayValue += "`r`n`t`tOverride `#{0}" -f $i
                    $additionalSerializedDataSigningDisplayValue += "`r`n`t`t`tName: {0}" -f $override.Name
                    $additionalSerializedDataSigningDisplayValue += "`r`n`t`t`tEnabled: {0}" -f $override.Enabled
                    if ($override.OrgWideSetting) {
                        $additionalSerializedDataSigningDisplayValue += "`r`n`t`t`tSetting applies to all servers of the organization"
                    } else {
                        $additionalSerializedDataSigningDisplayValue += "`r`n`t`t`tSetting applies to the following server(s) of the organization:"
                        foreach ($server in $override.Server) {
                            $additionalSerializedDataSigningDisplayValue += "`r`n`t`t`t{0}" -f $server
                        }
                    }
                }
                $additionalSerializedDataSigningDisplayValue += $serializedDataSigningConfigurationWarning
            } else {
                Write-Verbose "SerializedDataSigning is not configured via SettingOverride and is considered disabled"
                $serializedDataSigningState = $false
            }
        } else {
            Write-Verbose "Checking Registry Value for SerializedDataSigning configuration state"
            if ($serializedDataSigningInformation -eq 1) {
                Write-Verbose "SerializedDataSigning enabled via Registry Value"
                $serializedDataSigningState = ("$($true) - We recommend not to turn on this feature on Exchange 2013 for now")
            } else {
                Write-Verbose "SerializedDataSigning not configured or explicitly disabled via Registry Value"
                $serializedDataSigningWriteType = "Grey"
                $serializedDataSigningState = $false
            }
        }

        $params = $baseParams + @{
            Name             = "SerializedDataSigning Enabled"
            Details          = $serializedDataSigningState
            DisplayWriteType = $serializedDataSigningWriteType
        }
        Add-AnalyzedResultInformation @params

        if ($null -ne $additionalSerializedDataSigningDisplayValue) {
            $params = $baseParams + @{
                Details                = $additionalSerializedDataSigningDisplayValue
                DisplayWriteType       = $serializedDataSigningWriteType
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params
        }
    } else {
        Write-Verbose "SerializedDataSigning isn't available because we are on role: $($exchangeInformation.BuildInformation.ServerRole) build: $exchangeBuild"
    }
}
