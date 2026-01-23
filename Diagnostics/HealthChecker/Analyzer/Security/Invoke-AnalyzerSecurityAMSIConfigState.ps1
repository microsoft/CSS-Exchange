# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
. $PSScriptRoot\..\Get-FilteredSettingOverrideInformation.ps1
. $PSScriptRoot\..\..\..\..\Shared\CompareExchangeBuildLevel.ps1
. $PSScriptRoot\..\..\..\..\Shared\ScriptBlockFunctions\RemotePipelineHandlerFunctions.ps1

function Invoke-AnalyzerSecurityAMSIConfigState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ref]$AnalyzeResults,

        [Parameter(Mandatory = $true)]
        [object]$HealthServerObject,

        [Parameter(Mandatory = $true)]
        [object]$DisplayGroupingKey
    )

    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $exchangeInformation = $HealthServerObject.ExchangeInformation
    $exchangeCU = $exchangeInformation.BuildInformation.CU
    $osInformation = $HealthServerObject.OSInformation
    $baseParams = @{
        AnalyzedInformation = $AnalyzeResults
        DisplayGroupingKey  = $DisplayGroupingKey
    }

    # AMSI integration is only available on Windows Server 2016 or higher and only on
    # Exchange Server 2016 CU21+ or Exchange Server 2019 CU10+.
    # AMSI is also not available on Edge Transport Servers (no http component available).
    $isE16CU21Plus = $null
    $isE19CU10Plus = $null
    $isExSeRtmPlus = $null
    Test-ExchangeBuildGreaterOrEqualThanBuild -CurrentExchangeBuild $exchangeInformation.BuildInformation.VersionInformation -Version "Exchange2016" -CU "CU21" |
        Invoke-RemotePipelineHandler -Result ([ref]$isE16CU21Plus)
    Test-ExchangeBuildGreaterOrEqualThanBuild -CurrentExchangeBuild $exchangeInformation.BuildInformation.VersionInformation -Version "Exchange2019" -CU "CU10" |
        Invoke-RemotePipelineHandler -Result ([ref]$isE19CU10Plus)
    Test-ExchangeBuildGreaterOrEqualThanBuild -CurrentExchangeBuild $exchangeInformation.BuildInformation.VersionInformation -Version "ExchangeSE" -CU "RTM" |
        Invoke-RemotePipelineHandler -Result ([ref]$isExSeRtmPlus)

    # AMSI is available starting with Windows Server 2016
    if (($osInformation.BuildInformation.BuildVersion -ge [System.Version]"10.0.0.0") -and
        (($isE16CU21Plus) -or
        ($isE19CU10Plus) -or
        ($isExSeRtmPlus)) -and
        ($exchangeInformation.GetExchangeServer.IsEdgeServer -eq $false)) {

        # Query Setting Override configuration that controls AMSI integration in Exchange Server.
        # The "Cafe\HttpRequestFiltering\Enabled" setting determines whether AMSI scanning is active.
        $filterSettingOverrideParams = @{
            ExchangeSettingOverride = $HealthServerObject.ExchangeInformation.SettingOverrides
            GetSettingOverride      = $HealthServerObject.OrganizationInformation.GetSettingOverride
            FilterServer            = $HealthServerObject.ServerName
            FilterServerVersion     = $exchangeInformation.BuildInformation.VersionInformation.BuildVersion
            FilterComponentName     = "Cafe"
            FilterSectionName       = "HttpRequestFiltering"
            FilterParameterName     = "Enabled"
        }

        # Query returns only accepted (valid) and unique Setting Override values that apply to this server
        $amsiInformation = $null
        Get-FilteredSettingOverrideInformation @filterSettingOverrideParams | Invoke-RemotePipelineHandlerList -Result ([ref]$amsiInformation)
        $amsiWriteType = "Yellow"
        $amsiConfigurationWarning = "`r`n`t`tThis may pose a security risk to your servers"
        $amsiMoreInfo = "More Information: https://aka.ms/HC-AMSIExchange"
        $amsiMoreInformationDisplay = $false
        $amsiConfigurationUnknown = "Exchange AMSI integration state is unknown"
        $additionalAMSIDisplayValue = $null

        if ($amsiInformation.Count -eq 0) {
            # No Setting Override found means AMSI uses the default state (enabled) - this is the expected secure configuration
            $amsiWriteType = "Green"
            $amsiState = "True"
        } elseif ($amsiInformation -eq "Unknown") {
            $additionalAMSIDisplayValue = "Unable to query Exchange AMSI integration state"
        } elseif ($amsiInformation.Count -eq 1) {
            $amsiState = $amsiInformation.ParameterValue
            if ($amsiInformation.ParameterValue -eq "False") {
                $additionalAMSIDisplayValue = "Setting applies to the server" + $amsiConfigurationWarning + "`r`n`t`t" + $amsiMoreInfo
            } elseif ($amsiInformation.ParameterValue -eq "True") {
                $amsiWriteType = "Green"
            } else {
                $additionalAMSIDisplayValue = $amsiConfigurationUnknown + " - Setting Override Name: $($amsiInformation.Name)"
                $additionalAMSIDisplayValue += $amsiConfigurationWarning + "`r`n`t`t" + $amsiMoreInfo
            }
        } else {
            $amsiState = "Multiple overrides detected"
            $additionalAMSIDisplayValue = $amsiConfigurationUnknown + " - Multi Setting Overrides Applied: $([string]::Join(", ", [array]$amsiInformation.Name))"
            $additionalAMSIDisplayValue += $amsiConfigurationWarning + "`r`n`t`t" + $amsiMoreInfo
        }

        $params = $baseParams + @{
            Name             = "AMSI Enabled"
            Details          = $amsiState
            DisplayWriteType = $amsiWriteType
        }
        Add-AnalyzedResultInformation @params

        if ($null -ne $additionalAMSIDisplayValue) {
            $params = $baseParams + @{
                Details                = $additionalAMSIDisplayValue
                DisplayWriteType       = $amsiWriteType
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params
        }

        <#
            AMSI Request Body Scanning Feature (introduced with Nov24SU, enabled by default starting with Aug25SU):
            This feature extends AMSI protection to scan HTTP request bodies, not just URLs/headers.

            Prerequisites:
            - AMSI must be enabled (HttpRequestFiltering\Enabled = True) for body scanning to work
            - Starting with Aug25SU, EnabledAll defaults to True (body scanning enabled for all protocols)

            Configuration scenarios we check for:
            1. Body scanning enabled + AMSI enabled = Good (show as enabled)
            2. Body scanning enabled + AMSI disabled = Misconfiguration warning (body scanning won't work)
            3. Body size blocking enabled = Warning that requests over 1MB will be rejected (works regardless of AMSI state)
        #>

        $isAug25SuOrGreater = Test-ExchangeBuildGreaterOrEqualThanSecurityPatch -CurrentExchangeBuild $exchangeInformation.BuildInformation.VersionInformation -SUName "Aug25SU"
        $amsiStateEnabled = "true" -eq $amsiState

        # Query Setting Override for AMSI body scanning - can be enabled globally (EnabledAll) or per-protocol
        # Protocols include: Api, AutoD, Ecp, Ews, Mapi, Eas, Oab, Owa, PowerShell, Others
        $filterSettingOverrideParams.FilterSectionName = "AmsiRequestBodyScanning"
        $filterSettingOverrideParams.FilterParameterName = @("EnabledAll", "EnabledApi", "EnabledAutoD", "EnabledEcp",
            "EnabledEws", "EnabledMapi", "EnabledEas", "EnabledOab", "EnabledOwa", "EnabledPowerShell", "EnabledOthers")
        [array]$amsiRequestBodyScanning = $null

        Get-FilteredSettingOverrideInformation @filterSettingOverrideParams | Invoke-RemotePipelineHandlerList -Result ([ref]$amsiRequestBodyScanning)

        # Query Setting Override for request body size blocking feature.
        # When enabled, HTTP requests with bodies larger than 1MB are blocked entirely.
        # WARNING: This blocking occurs regardless of whether AMSI is enabled or disabled.
        $filterSettingOverrideParams.FilterSectionName = "BlockRequestBodyGreaterThanMaxScanSize"
        [array]$amsiBlockRequestBodyGreater = $null

        Get-FilteredSettingOverrideInformation @filterSettingOverrideParams | Invoke-RemotePipelineHandlerList -Result ([ref]$amsiBlockRequestBodyGreater)

        # Extract any "EnabledAll" Setting Override values - this parameter controls body scanning for all protocols at once
        [array]$enabledAllValues = $amsiRequestBodyScanning | Where-Object { $_.ParameterName -eq "EnabledAll" }

        # Check if EnabledAll is explicitly set to True via Setting Override
        [array]$enabledAllTrueValues = $enabledAllValues | Where-Object { $_.ParameterValue -eq "True" }

        # Determine if body scanning is enabled by default for all protocols:
        # True if: running Aug25SU or later (where EnabledAll defaults to True) AND no Setting Override explicitly disables it
        [array]$enabledAllFalseValues = $enabledAllValues | Where-Object { $_.ParameterValue -eq "False" }
        $defaultEnabledAll = $isAug25SuOrGreater -and ($enabledAllFalseValues.Count -eq 0)
        Write-Verbose "Enabled All Default Value Set to '$defaultEnabledAll'"

        # Collect Setting Overrides that explicitly enable body scanning for specific protocols (e.g., EnabledEcp=True)
        [array]$amsiRequestBodyScanningEnabledProtocols = $amsiRequestBodyScanning | Where-Object { $_.ParameterValue -eq "True" }

        # Collect Setting Overrides that explicitly disable body scanning for specific protocols (e.g., EnabledEcp=False)
        [array]$amsiRequestBodyScanningDisabledProtocols = $amsiRequestBodyScanning | Where-Object { $_.ParameterValue -eq "False" }

        # Determine if AMSI body scanning is enabled (for any protocol):
        # Matches Exchange Server logic: EnabledAll=True enables for all protocols,
        # OR any individual protocol can be enabled independently (EnabledAll=False does NOT block individual settings)
        $amsiRequestBodyScanningEnabled = $defaultEnabledAll -or
        ($enabledAllTrueValues.Count -gt 0) -or
        ($amsiRequestBodyScanningEnabledProtocols.Count -gt 0)

        # Check if request body size blocking is explicitly enabled via Setting Override
        $amsiBlockRequestBodyEnabled = $amsiBlockRequestBodyGreater.Count -gt 0 -and
        ($null -ne ($amsiBlockRequestBodyGreater | Where-Object { $_.ParameterValue -eq "True" }))

        # Calculate display value: True only if both AMSI and body scanning are enabled
        $requestBodyDisplayValue = $amsiStateEnabled -and $amsiRequestBodyScanningEnabled
        $requestBodyDisplayType = $requestBodySizeBlockDisplayType = "Grey"
        $requestBodySizeBlockDisplayValue = $false

        # Warn if body size blocking is enabled - this can impact legitimate large requests (e.g., file uploads)
        if ($amsiBlockRequestBodyEnabled) {
            $requestBodySizeBlockDisplayValue = "$true - WARNING: Requests over 1MB will be blocked."
            $requestBodySizeBlockDisplayType = "Yellow"
            $amsiMoreInformationDisplay = $true
        }

        # Check for misconfiguration: body scanning features configured but AMSI itself is disabled
        if ($amsiStateEnabled -eq $false) {
            # Body scanning requires AMSI to be enabled - warn about this ineffective configuration
            if ($amsiRequestBodyScanningEnabled) {
                $requestBodyDisplayValue = "$true - WARNING: AMSI not enabled"
                $requestBodyDisplayType = "Yellow"
                $amsiMoreInformationDisplay = $true
            }
            # Body size blocking works independently of AMSI state - warn that blocking will still occur
            if ($amsiBlockRequestBodyEnabled) {
                $requestBodySizeBlockDisplayValue += " AMSI not enabled and this will still be triggered."
                $amsiMoreInformationDisplay = $true
            }
        }

        if ($amsiRequestBodyScanningEnabled -eq $false) {
            $requestBodyDisplayType = "Yellow"
        }

        $params = $baseParams + @{
            Name             = "AMSI Request Body Scanning"
            Details          = $requestBodyDisplayValue
            DisplayWriteType = $requestBodyDisplayType
        }
        Add-AnalyzedResultInformation @params

        # Display protocol-specific body scanning configuration details.
        # This provides additional context when body scanning is enabled and there are protocol-level overrides.
        # Skip if EnabledAll=True is explicitly set, since that covers all protocols uniformly.
        if ($amsiRequestBodyScanningEnabled -and
            ($amsiRequestBodyScanningEnabledProtocols.Count -gt 0 -or
            $amsiRequestBodyScanningDisabledProtocols.Count -gt 0) -and
            $amsiRequestBodyScanningEnabledProtocols.ParameterName -notcontains "EnabledAll") {

            if ($defaultEnabledAll) {
                # Aug25SU+ has body scanning enabled by default for all protocols.
                # Show which protocols are explicitly disabled, or confirm default-enabled state.
                if ($amsiRequestBodyScanningDisabledProtocols.Count -gt 0) {
                    $disabledProtocols = $amsiRequestBodyScanningDisabledProtocols | ForEach-Object { $_.ParameterName -replace "^Enabled", "" }
                    $protocolsDisplay = "Body scanning is disabled via Setting Override for protocols: " + ($disabledProtocols -join ", ")
                } else {
                    $protocolsDisplay = "Body scanning enabled by default for all protocols"
                }
            } else {
                # Pre-Aug25SU or EnabledAll explicitly disabled: show which protocols are explicitly enabled.
                $enabledProtocols = $amsiRequestBodyScanningEnabledProtocols | ForEach-Object { $_.ParameterName -replace "^Enabled", "" }
                $protocolsDisplay = "Enabled for protocols: " + ($enabledProtocols -join ", ")
            }
            $params = $baseParams + @{
                Details                = $protocolsDisplay
                DisplayCustomTabNumber = 2
                DisplayWriteType       = $requestBodyDisplayType
            }
            Add-AnalyzedResultInformation @params
        }

        $params = $baseParams + @{
            Name             = "AMSI Request Body Size Block"
            Details          = $requestBodySizeBlockDisplayValue
            DisplayWriteType = $requestBodySizeBlockDisplayType
        }
        Add-AnalyzedResultInformation @params

        $isNov24SUOrGreater = $false
        Test-ExchangeBuildGreaterOrEqualThanSecurityPatch -CurrentExchangeBuild $exchangeInformation.BuildInformation.VersionInformation -SUName "Nov24SU" |
            Invoke-RemotePipelineHandler -Result ([ref]$isNov24SUOrGreater)
        if (($amsiRequestBodyScanningEnabled -or
                $amsiBlockRequestBodyEnabled) -and
            -not ($isNov24SUOrGreater)) {
            $params = $baseParams + @{
                Details                = "AMSI Body Scanning Option(s) enabled, but not applicable due to the version of Exchange. Must be on Nov24SU or greater to have this feature enabled."
                DisplayCustomTabNumber = 2
                DisplayWriteType       = "Yellow"
            }
            Add-AnalyzedResultInformation @params
        }

        if ($amsiMoreInformationDisplay) {
            $params = $baseParams + @{
                Details                = $amsiMoreInfo
                DisplayCustomTabNumber = 2
                DisplayWriteType       = "Yellow"
            }
            Add-AnalyzedResultInformation @params
        }
    } else {
        Write-Verbose "AMSI integration is not available because we are on: $($exchangeInformation.BuildInformation.MajorVersion) $exchangeCU"
    }
    Write-Verbose "Completed: $($MyInvocation.MyCommand) and took $($stopWatch.Elapsed.TotalSeconds) seconds"
}
