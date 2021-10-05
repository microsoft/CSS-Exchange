# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Get-RemoteRegistryValue.ps1
. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
. $PSScriptRoot\..\..\Helpers\Invoke-CatchActions.ps1
. $PSScriptRoot\Get-ExchangeAdSchemaClass.ps1
. $PSScriptRoot\Get-ExchangeApplicationConfigurationFileValidation.ps1
. $PSScriptRoot\Get-ExchangeAppPoolsInformation.ps1
. $PSScriptRoot\Get-ExchangeBuildVersionInformation.ps1
. $PSScriptRoot\Get-ExchangeEmergencyMitigationServiceState.ps1
. $PSScriptRoot\Get-ExchangeServerCertificates.ps1
. $PSScriptRoot\Get-ExchangeServerMaintenanceState.ps1
. $PSScriptRoot\Get-ExchangeUpdates.ps1
. $PSScriptRoot\Get-ExSetupDetails.ps1
. $PSScriptRoot\Get-ServerRole.ps1
Function Get-ExchangeInformation {
    param(
        [HealthChecker.OSServerVersion]$OSMajorVersion
    )
    Write-Verbose "Calling: $($MyInvocation.MyCommand) Passed: OSMajorVersion: $OSMajorVersion"
    [HealthChecker.ExchangeInformation]$exchangeInformation = New-Object -TypeName HealthChecker.ExchangeInformation
    $exchangeInformation.GetExchangeServer = (Get-ExchangeServer -Identity $Script:Server -Status)
    $exchangeInformation.ExchangeCertificates = Get-ExchangeServerCertificates
    $buildInformation = $exchangeInformation.BuildInformation
    $buildVersionInfo = Get-ExchangeBuildVersionInformation -AdminDisplayVersion $exchangeInformation.GetExchangeServer.AdminDisplayVersion
    $buildInformation.MajorVersion = ([HealthChecker.ExchangeMajorVersion]$buildVersionInfo.MajorVersion)
    $buildInformation.BuildNumber = "{0}.{1}.{2}.{3}" -f $buildVersionInfo.Major, $buildVersionInfo.Minor, $buildVersionInfo.Build, $buildVersionInfo.Revision
    $buildInformation.ServerRole = (Get-ServerRole -ExchangeServerObj $exchangeInformation.GetExchangeServer)
    $buildInformation.ExchangeSetup = Get-ExSetupDetails

    if ($buildInformation.ServerRole -le [HealthChecker.ExchangeServerRole]::Mailbox ) {
        try {
            $exchangeInformation.GetMailboxServer = (Get-MailboxServer -Identity $Script:Server -ErrorAction Stop)
        } catch {
            Write-Verbose "Failed to run Get-MailboxServer"
            Invoke-CatchActions
        }
    }

    if (($buildInformation.MajorVersion -ge [HealthChecker.ExchangeMajorVersion]::Exchange2016 -and
            $buildInformation.ServerRole -le [HealthChecker.ExchangeServerRole]::Mailbox) -or
        ($buildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2013 -and
            ($buildInformation.ServerRole -eq [HealthChecker.ExchangeServerRole]::ClientAccess -or
        $buildInformation.ServerRole -eq [HealthChecker.ExchangeServerRole]::MultiRole))) {
        $exchangeInformation.GetOwaVirtualDirectory = Get-OwaVirtualDirectory -Identity ("{0}\owa (Default Web Site)" -f $Script:Server) -ADPropertiesOnly
        $exchangeInformation.GetWebServicesVirtualDirectory = Get-WebServicesVirtualDirectory -Server $Script:Server
    }

    if ($Script:ExchangeShellComputer.ToolsOnly) {
        $buildInformation.LocalBuildNumber = "{0}.{1}.{2}.{3}" -f $Script:ExchangeShellComputer.Major, $Script:ExchangeShellComputer.Minor, `
            $Script:ExchangeShellComputer.Build, `
            $Script:ExchangeShellComputer.Revision
    }

    #Exchange 2013 or greater
    if ($buildInformation.MajorVersion -ge [HealthChecker.ExchangeMajorVersion]::Exchange2013) {
        $netFrameworkExchange = $exchangeInformation.NETFramework
        $buildAndRevision = $buildVersionInfo.BuildVersion
        Write-Verbose "The build and revision number: $buildAndRevision"
        #Build Numbers: https://docs.microsoft.com/en-us/Exchange/new-features/build-numbers-and-release-dates?view=exchserver-2019
        if ($buildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2019) {
            Write-Verbose "Exchange 2019 is detected. Checking build number..."
            $buildInformation.FriendlyName = "Exchange 2019 "

            #Exchange 2019 Information
            if ($buildAndRevision -lt 330.5) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::RTM
                $buildInformation.FriendlyName += "RTM"
                $buildInformation.ReleaseDate = "10/22/2018"
            } elseif ($buildAndRevision -lt 397.3) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU1
                $buildInformation.FriendlyName += "CU1"
                $buildInformation.ReleaseDate = "02/12/2019"
            } elseif ($buildAndRevision -lt 464.5) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU2
                $buildInformation.FriendlyName += "CU2"
                $buildInformation.ReleaseDate = "06/18/2019"
            } elseif ($buildAndRevision -lt 529.5) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU3
                $buildInformation.FriendlyName += "CU3"
                $buildInformation.ReleaseDate = "09/17/2019"
            } elseif ($buildAndRevision -lt 595.3) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU4
                $buildInformation.FriendlyName += "CU4"
                $buildInformation.ReleaseDate = "12/17/2019"
            } elseif ($buildAndRevision -lt 659.4) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU5
                $buildInformation.FriendlyName += "CU5"
                $buildInformation.ReleaseDate = "03/17/2020"
            } elseif ($buildAndRevision -lt 721.2) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU6
                $buildInformation.FriendlyName += "CU6"
                $buildInformation.ReleaseDate = "06/16/2020"
            } elseif ($buildAndRevision -lt 792.3) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU7
                $buildInformation.FriendlyName += "CU7"
                $buildInformation.ReleaseDate = "09/15/2020"
            } elseif ($buildAndRevision -lt 858.5) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU8
                $buildInformation.FriendlyName += "CU8"
                $buildInformation.ReleaseDate = "12/15/2020"
            } elseif ($buildAndRevision -lt 922.7) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU9
                $buildInformation.FriendlyName += "CU9"
                $buildInformation.ReleaseDate = "03/16/2021"
            } elseif ($buildAndRevision -lt 986.5) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU10
                $buildInformation.FriendlyName += "CU10"
                $buildInformation.ReleaseDate = "06/29/2021"
                $buildInformation.SupportedBuild = $true
            } elseif ($buildAndRevision -ge 986.5) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU11
                $buildInformation.FriendlyName += "CU11"
                $buildInformation.ReleaseDate = "09/28/2021"
                $buildInformation.SupportedBuild = $true
            }

            #Exchange 2019 .NET Information
            if ($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU2) {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d2
                $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d2
            } elseif ($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU4) {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d2
                $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d8
            } else {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d8
                $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d8
            }
        } elseif ($buildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2016) {
            Write-Verbose "Exchange 2016 is detected. Checking build number..."
            $buildInformation.FriendlyName = "Exchange 2016 "

            #Exchange 2016 Information
            if ($buildAndRevision -lt 466.34) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU1
                $buildInformation.FriendlyName += "CU1"
                $buildInformation.ReleaseDate = "03/15/2016"
            } elseif ($buildAndRevision -lt 544.27) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU2
                $buildInformation.FriendlyName += "CU2"
                $buildInformation.ReleaseDate = "06/21/2016"
            } elseif ($buildAndRevision -lt 669.32) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU3
                $buildInformation.FriendlyName += "CU3"
                $buildInformation.ReleaseDate = "09/20/2016"
            } elseif ($buildAndRevision -lt 845.34) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU4
                $buildInformation.FriendlyName += "CU4"
                $buildInformation.ReleaseDate = "12/13/2016"
            } elseif ($buildAndRevision -lt 1034.26) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU5
                $buildInformation.FriendlyName += "CU5"
                $buildInformation.ReleaseDate = "03/21/2017"
            } elseif ($buildAndRevision -lt 1261.35) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU6
                $buildInformation.FriendlyName += "CU6"
                $buildInformation.ReleaseDate = "06/24/2017"
            } elseif ($buildAndRevision -lt 1415.2) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU7
                $buildInformation.FriendlyName += "CU7"
                $buildInformation.ReleaseDate = "09/16/2017"
            } elseif ($buildAndRevision -lt 1466.3) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU8
                $buildInformation.FriendlyName += "CU8"
                $buildInformation.ReleaseDate = "12/19/2017"
            } elseif ($buildAndRevision -lt 1531.3) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU9
                $buildInformation.FriendlyName += "CU9"
                $buildInformation.ReleaseDate = "03/20/2018"
            } elseif ($buildAndRevision -lt 1591.10) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU10
                $buildInformation.FriendlyName += "CU10"
                $buildInformation.ReleaseDate = "06/19/2018"
            } elseif ($buildAndRevision -lt 1713.5) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU11
                $buildInformation.FriendlyName += "CU11"
                $buildInformation.ReleaseDate = "10/16/2018"
            } elseif ($buildAndRevision -lt 1779.2) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU12
                $buildInformation.FriendlyName += "CU12"
                $buildInformation.ReleaseDate = "02/12/2019"
            } elseif ($buildAndRevision -lt 1847.3) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU13
                $buildInformation.FriendlyName += "CU13"
                $buildInformation.ReleaseDate = "06/18/2019"
            } elseif ($buildAndRevision -lt 1913.5) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU14
                $buildInformation.FriendlyName += "CU14"
                $buildInformation.ReleaseDate = "09/17/2019"
            } elseif ($buildAndRevision -lt 1979.3) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU15
                $buildInformation.FriendlyName += "CU15"
                $buildInformation.ReleaseDate = "12/17/2019"
            } elseif ($buildAndRevision -lt 2044.4) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU16
                $buildInformation.FriendlyName += "CU16"
                $buildInformation.ReleaseDate = "03/17/2020"
            } elseif ($buildAndRevision -lt 2106.2) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU17
                $buildInformation.FriendlyName += "CU17"
                $buildInformation.ReleaseDate = "06/16/2020"
            } elseif ($buildAndRevision -lt 2176.2) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU18
                $buildInformation.FriendlyName += "CU18"
                $buildInformation.ReleaseDate = "09/15/2020"
            } elseif ($buildAndRevision -lt 2242.4) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU19
                $buildInformation.FriendlyName += "CU19"
                $buildInformation.ReleaseDate = "12/15/2020"
            } elseif ($buildAndRevision -lt 2308.8) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU20
                $buildInformation.FriendlyName += "CU20"
                $buildInformation.ReleaseDate = "03/16/2021"
            } elseif ($buildAndRevision -lt 2375.7) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU21
                $buildInformation.FriendlyName += "CU21"
                $buildInformation.ReleaseDate = "06/29/2021"
                $buildInformation.SupportedBuild = $true
            } elseif ($buildAndRevision -ge 2375.7) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU22
                $buildInformation.FriendlyName += "CU22"
                $buildInformation.ReleaseDate = "09/28/2021"
                $buildInformation.SupportedBuild = $true
            }

            #Exchange 2016 .NET Information
            if ($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU2) {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d5d2wFix
                $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d5d2wFix
            } elseif ($buildInformation.CU -eq [HealthChecker.ExchangeCULevel]::CU2) {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d5d2wFix
                $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d1wFix
            } elseif ($buildInformation.CU -eq [HealthChecker.ExchangeCULevel]::CU3) {

                if ($OSMajorVersion -eq [HealthChecker.OSServerVersion]::Windows2016) {
                    $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d5d2wFix
                    $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d2
                } else {
                    $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d5d2wFix
                    $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d1wFix
                }
            } elseif ($buildInformation.CU -eq [HealthChecker.ExchangeCULevel]::CU4) {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d5d2wFix
                $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d2
            } elseif ($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU8) {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d2
                $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d2
            } elseif ($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU10) {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d2
                $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d1
            } elseif ($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU11) {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d1
                $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d1
            } elseif ($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU13) {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d1
                $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d2
            } elseif ($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU15) {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d2
                $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d8
            } else {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d8
                $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d8
            }
        } else {
            Write-Verbose "Exchange 2013 is detected. Checking build number..."
            $buildInformation.FriendlyName = "Exchange 2013 "

            #Exchange 2013 Information
            if ($buildAndRevision -lt 712.24) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU1
                $buildInformation.FriendlyName += "CU1"
                $buildInformation.ReleaseDate = "04/02/2013"
            } elseif ($buildAndRevision -lt 775.38) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU2
                $buildInformation.FriendlyName += "CU2"
                $buildInformation.ReleaseDate = "07/09/2013"
            } elseif ($buildAndRevision -lt 847.32) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU3
                $buildInformation.FriendlyName += "CU3"
                $buildInformation.ReleaseDate = "11/25/2013"
            } elseif ($buildAndRevision -lt 913.22) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU4
                $buildInformation.FriendlyName += "CU4"
                $buildInformation.ReleaseDate = "02/25/2014"
            } elseif ($buildAndRevision -lt 995.29) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU5
                $buildInformation.FriendlyName += "CU5"
                $buildInformation.ReleaseDate = "05/27/2014"
            } elseif ($buildAndRevision -lt 1044.25) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU6
                $buildInformation.FriendlyName += "CU6"
                $buildInformation.ReleaseDate = "08/26/2014"
            } elseif ($buildAndRevision -lt 1076.9) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU7
                $buildInformation.FriendlyName += "CU7"
                $buildInformation.ReleaseDate = "12/09/2014"
            } elseif ($buildAndRevision -lt 1104.5) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU8
                $buildInformation.FriendlyName += "CU8"
                $buildInformation.ReleaseDate = "03/17/2015"
            } elseif ($buildAndRevision -lt 1130.7) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU9
                $buildInformation.FriendlyName += "CU9"
                $buildInformation.ReleaseDate = "06/17/2015"
            } elseif ($buildAndRevision -lt 1156.6) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU10
                $buildInformation.FriendlyName += "CU10"
                $buildInformation.ReleaseDate = "09/15/2015"
            } elseif ($buildAndRevision -lt 1178.4) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU11
                $buildInformation.FriendlyName += "CU11"
                $buildInformation.ReleaseDate = "12/15/2015"
            } elseif ($buildAndRevision -lt 1210.3) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU12
                $buildInformation.FriendlyName += "CU12"
                $buildInformation.ReleaseDate = "03/15/2016"
            } elseif ($buildAndRevision -lt 1236.3) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU13
                $buildInformation.FriendlyName += "CU13"
                $buildInformation.ReleaseDate = "06/21/2016"
            } elseif ($buildAndRevision -lt 1263.5) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU14
                $buildInformation.FriendlyName += "CU14"
                $buildInformation.ReleaseDate = "09/20/2016"
            } elseif ($buildAndRevision -lt 1293.2) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU15
                $buildInformation.FriendlyName += "CU15"
                $buildInformation.ReleaseDate = "12/13/2016"
            } elseif ($buildAndRevision -lt 1320.4) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU16
                $buildInformation.FriendlyName += "CU16"
                $buildInformation.ReleaseDate = "03/21/2017"
            } elseif ($buildAndRevision -lt 1347.2) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU17
                $buildInformation.FriendlyName += "CU17"
                $buildInformation.ReleaseDate = "06/24/2017"
            } elseif ($buildAndRevision -lt 1365.1) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU18
                $buildInformation.FriendlyName += "CU18"
                $buildInformation.ReleaseDate = "09/16/2017"
            } elseif ($buildAndRevision -lt 1367.3) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU19
                $buildInformation.FriendlyName += "CU19"
                $buildInformation.ReleaseDate = "12/19/2017"
            } elseif ($buildAndRevision -lt 1395.4) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU20
                $buildInformation.FriendlyName += "CU20"
                $buildInformation.ReleaseDate = "03/20/2018"
            } elseif ($buildAndRevision -lt 1473.3) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU21
                $buildInformation.FriendlyName += "CU21"
                $buildInformation.ReleaseDate = "06/19/2018"
            } elseif ($buildAndRevision -lt 1497.2) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU22
                $buildInformation.FriendlyName += "CU22"
                $buildInformation.ReleaseDate = "02/12/2019"
            } elseif ($buildAndRevision -ge 1497.2) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU23
                $buildInformation.FriendlyName += "CU23"
                $buildInformation.ReleaseDate = "06/18/2019"
                $buildInformation.SupportedBuild = $true
            }

            #Exchange 2013 .NET Information
            if ($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU4) {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d5
                $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d5
            } elseif ($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU13) {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d5
                $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d5d2wFix
            } elseif ($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU15) {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d5
                $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d1wFix
            } elseif ($buildInformation.CU -eq [HealthChecker.ExchangeCULevel]::CU15) {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d5d1
                $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d2
            } elseif ($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU19) {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d2
                $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d2
            } elseif ($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU21) {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d2
                $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d1
            } elseif ($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU23) {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d1
                $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d2
            } else {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d2
                $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d8
            }
        }

        try {
            $organizationConfig = Get-OrganizationConfig -ErrorAction Stop
            $exchangeInformation.GetOrganizationConfig = $organizationConfig
        } catch {
            Write-Yellow "Failed to run Get-OrganizationConfig."
            Invoke-CatchActions
        }

        $mitigationsEnabled = $null
        if ($null -ne $organizationConfig) {
            $mitigationsEnabled = $organizationConfig.MitigationsEnabled
        }

        $exchangeInformation.ExchangeEmergencyMitigationService = Get-ExchangeEmergencyMitigationServiceState `
            -RequiredInformation ([PSCustomObject]@{
                ComputerName       = $Script:Server
                MitigationsEnabled = $mitigationsEnabled
                GetExchangeServer  = $exchangeInformation.GetExchangeServer
            }) `
            -CatchActionFunction ${Function:Invoke-CatchActions}

        if ($null -ne $organizationConfig) {
            $exchangeInformation.MapiHttpEnabled = $organizationConfig.MapiHttpEnabled
            if ($null -ne $organizationConfig.EnableDownloadDomains) {
                $exchangeInformation.EnableDownloadDomains = $organizationConfig.EnableDownloadDomains
            }
        } else {
            Write-Verbose "MAPI HTTP Enabled and Download Domains Enabled results not accurate"
        }

        if ($buildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::Edge) {
            $exchangeInformation.ApplicationPools = Get-ExchangeAppPoolsInformation
            try {
                $exchangeInformation.GetHybridConfiguration = Get-HybridConfiguration -ErrorAction Stop
            } catch {
                Write-Yellow "Failed to run Get-HybridConfiguration"
                Invoke-CatchActions
            }
        }

        $serverExchangeBinDirectory = Invoke-ScriptBlockHandler -ComputerName $Script:Server `
            -ScriptBlockDescription "Getting Exchange Bin Directory" `
            -CatchActionFunction ${Function:Invoke-CatchActions} `
            -ScriptBlock {
            "{0}Bin\" -f (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup).MsiInstallPath
        }
        Write-Verbose "Found Exchange Bin: $serverExchangeBinDirectory"
        $exchangeInformation.ApplicationConfigFileStatus = Get-ExchangeApplicationConfigurationFileValidation -ConfigFileLocation ("{0}EdgeTransport.exe.config" -f $serverExchangeBinDirectory)

        $buildInformation.KBsInstalled = Get-ExchangeUpdates -ExchangeMajorVersion $buildInformation.MajorVersion
        if (($null -ne $buildInformation.KBsInstalled) -and ($buildInformation.KBsInstalled -like "*KB5000871*")) {
            Write-Verbose "March 2021 SU: KB5000871 was detected on the system"
            $buildInformation.March2021SUInstalled = $true
        } else {
            Write-Verbose "March 2021 SU: KB5000871 was not detected on the system"
            $buildInformation.March2021SUInstalled = $false
        }

        Write-Verbose "Query schema class information for CVE-2021-34470 testing"
        try {
            $exchangeInformation.msExchStorageGroup = Get-ExchangeAdSchemaClass -SchemaClassName "ms-Exch-Storage-Group"
        } catch {
            Write-Verbose "Failed to run Get-ExchangeAdSchemaClass"
            Invoke-CatchActions
        }

        $exchangeInformation.RegistryValues.CtsProcessorAffinityPercentage = Get-RemoteRegistryValue -MachineName $Script:Server `
            -SubKey "SOFTWARE\Microsoft\ExchangeServer\v15\Search\SystemParameters" `
            -GetValue "CtsProcessorAffinityPercentage" `
            -CatchActionFunction ${Function:Invoke-CatchActions}
        $exchangeInformation.RegistryValues.FipsAlgorithmPolicyEnabled = Get-RemoteRegistryValue -MachineName $Script:Server `
            -SubKey "SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" `
            -GetValue "Enabled" `
            -CatchActionFunction ${Function:Invoke-CatchActions}
        $exchangeInformation.ServerMaintenance = Get-ExchangeServerMaintenanceState -ComponentsToSkip "ForwardSyncDaemon", "ProvisioningRps"

        if (($buildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::ClientAccess) -and
            ($buildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::None)) {
            try {
                $testServiceHealthResults = Test-ServiceHealth -Server $Script:Server -ErrorAction Stop
                foreach ($notRunningService in $testServiceHealthResults.ServicesNotRunning) {
                    if ($exchangeInformation.ExchangeServicesNotRunning -notcontains $notRunningService) {
                        $exchangeInformation.ExchangeServicesNotRunning += $notRunningService
                    }
                }
            } catch {
                Write-Verbose "Failed to run Test-ServiceHealth"
                Invoke-CatchActions
            }
        }
    } elseif ($buildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2010) {
        Write-Verbose "Exchange 2010 detected."
        $buildInformation.FriendlyName = "Exchange 2010"
        $buildInformation.BuildNumber = $exchangeInformation.GetExchangeServer.AdminDisplayVersion.ToString()
    }

    Write-Verbose "Exiting: Get-ExchangeInformation"
    return $exchangeInformation
}

