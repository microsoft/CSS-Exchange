Function Get-ExchangeInformation {
    param(
        [HealthChecker.OSServerVersion]$OSMajorVersion
    )
    Write-VerboseOutput("Calling: Get-ExchangeInformation")
    Write-VerboseOutput("Passed: OSMajorVersion: {0}" -f $OSMajorVersion)
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
        $exchangeInformation.GetMailboxServer = (Get-MailboxServer -Identity $Script:Server)
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
        Write-VerboseOutput("The build and revision number: {0}" -f $buildAndRevision)
        #Build Numbers: https://docs.microsoft.com/en-us/Exchange/new-features/build-numbers-and-release-dates?view=exchserver-2019
        if ($buildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2019) {
            Write-VerboseOutput("Exchange 2019 is detected. Checking build number...")
            $buildInformation.FriendlyName = "Exchange 2019 "

            #Exchange 2019 Information
            if ($buildAndRevision -lt 397.3) {
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
                $buildInformation.SupportedBuild = $true
            } elseif ($buildAndRevision -ge 792.3) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU8
                $buildInformation.FriendlyName += "CU8"
                $buildInformation.ReleaseDate = "12/15/2020"
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
            Write-VerboseOutput("Exchange 2016 is detected. Checking build number...")
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
                $buildInformation.SupportedBuild = $true
            } elseif ($buildAndRevision -ge 2176.2) {
                $buildInformation.CU = [HealthChecker.ExchangeCULevel]::CU19
                $buildInformation.FriendlyName += "CU19"
                $buildInformation.ReleaseDate = "12/15/2020"
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
            } elseif ($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU11) {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d2
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
            Write-VerboseOutput("Exchange 2013 is detected. Checking build number...")
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
            if ($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU12) {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d5d2wFix
                $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d5d2wFix
            } elseif ($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU15) {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d5d2wFix
                $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d1wFix
            } elseif ($buildInformation.CU -eq [HealthChecker.ExchangeCULevel]::CU15) {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d5d2wFix
                $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d2
            } elseif ($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU19) {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d2
                $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d2
            } elseif ($buildInformation.CU -lt [HealthChecker.ExchangeCULevel]::CU21) {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d6d2
                $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d1
            } elseif ($buildInformation.CU -le [HealthChecker.ExchangeCULevel]::CU22) {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d1
                $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d2
            } else {
                $netFrameworkExchange.MinSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d7d2
                $netFrameworkExchange.MaxSupportedVersion = [HealthChecker.NetMajorVersion]::Net4d8
            }
        }

        $exchangeInformation.MapiHttpEnabled = (Get-OrganizationConfig).MapiHttpEnabled

        if ($buildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::Edge) {
            $exchangeInformation.ApplicationPools = Get-ExchangeAppPoolsInformation
        }

        $buildInformation.KBsInstalled = Get-ExchangeUpdates -ExchangeMajorVersion $buildInformation.MajorVersion
        $exchangeInformation.RegistryValues.CtsProcessorAffinityPercentage = Invoke-RegistryGetValue -MachineName $Script:Server `
            -SubKey "SOFTWARE\Microsoft\ExchangeServer\v15\Search\SystemParameters" `
            -GetValue "CtsProcessorAffinityPercentage" `
            -CatchActionFunction ${Function:Invoke-CatchActions}
        $exchangeInformation.RegistryValues.FipsAlgorithmPolicyEnabled = Invoke-RegistryGetValue -MachineName $Script:Server `
            -SubKey "SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" `
            -GetValue "Enabled" `
            -CatchActionFunction ${Function:Invoke-CatchActions}
        $exchangeInformation.ServerMaintenance = Get-ExchangeServerMaintenanceState -ComponentsToSkip "ForwardSyncDaemon", "ProvisioningRps"

        if ($buildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::ClientAccess) {
            $exchangeInformation.ExchangeServicesNotRunning = Test-ServiceHealth -Server $Script:Server | ForEach-Object { $_.ServicesNotRunning }
        }
    } elseif ($buildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2010) {
        Write-VerboseOutput("Exchange 2010 detected.")
        $buildInformation.FriendlyName = "Exchange 2010"
        $buildInformation.BuildNumber = $exchangeInformation.GetExchangeServer.AdminDisplayVersion.ToString()
    }

    Write-VerboseOutput("Exiting: Get-ExchangeInformation")
    return $exchangeInformation
}