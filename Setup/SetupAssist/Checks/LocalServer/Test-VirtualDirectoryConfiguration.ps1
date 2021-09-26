# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-TestResult.ps1

function Test-VirtualDirectoryConfiguration {
    [CmdletBinding()]
    param ()

    begin {
        $problemsFound = $false
        $fixesPerformed = $false
        $appHostConfigPath = "$($env:WINDIR)\System32\inetsrv\config\applicationHost.config"
        $resultParams = @{
            TestName = "Virtual Directory Configuration"
        }
    }

    process {

        $owaVersion = (Get-ItemProperty "HKLM:\Software\Microsoft\ExchangeServer\v15\Setup\" -ErrorAction SilentlyContinue).OwaVersion
        $owaBasicVersion = (Get-ItemProperty "HKLM:\Software\Microsoft\ExchangeServer\v15\Setup\" -ErrorAction SilentlyContinue).OwaBasicVersion
        if ($null -eq $owaVersion -or $null -eq $owaBasicVersion) {
            return
        }

        $expectedVdirs = @(
            [PSCustomObject]@{DirectoryName = "Autodiscover (Default Web Site)"; Paths = @("/Autodiscover") },
            [PSCustomObject]@{DirectoryName = "Autodiscover (Exchange Back End)"; Paths = @("/Autodiscover") },
            [PSCustomObject]@{DirectoryName = "ecp (Default Web Site)"; Paths = @("/ecp") },
            [PSCustomObject]@{DirectoryName = "ecp (Exchange Back End)"; Paths = @("/ecp") },
            [PSCustomObject]@{DirectoryName = "EWS (Default Web Site)"; Paths = @("/EWS") },
            [PSCustomObject]@{DirectoryName = "EWS (Exchange Back End)"; Paths = @("/EWS", "/EWS/bin") },
            [PSCustomObject]@{DirectoryName = "mapi (Default Web Site)"; Paths = @("/mapi") },
            [PSCustomObject]@{DirectoryName = "Microsoft-Server-ActiveSync (Default Web Site)"; Paths = @("/Microsoft-Server-ActiveSync") },
            [PSCustomObject]@{DirectoryName = "Microsoft-Server-ActiveSync (Exchange Back End)"; Paths = @("/Microsoft-Server-ActiveSync") },
            [PSCustomObject]@{DirectoryName = "OAB (Default Web Site)"; Paths = @("/OAB") },
            [PSCustomObject]@{DirectoryName = "OAB (Exchange Back End)"; Paths = @("/OAB") },
            [PSCustomObject]@{DirectoryName = "owa (Default Web Site)"; Paths = @("/owa", "/owa/Calendar", "/owa/Integrated", "/owa/oma") },
            [PSCustomObject]@{DirectoryName = "owa (Exchange Back End)"; Paths = @("/owa", "/owa/Calendar") },
            [PSCustomObject]@{DirectoryName = "PowerShell (Default Web Site)"; Paths = @("/PowerShell") },
            [PSCustomObject]@{DirectoryName = "PowerShell (Exchange Back End)"; Paths = @("/PowerShell") },
            [PSCustomObject]@{DirectoryName = "PushNotifications (Exchange Back End)"; Paths = @("/PushNotifications") },
            [PSCustomObject]@{DirectoryName = "Rpc (Default Web Site)"; Paths = @("/Rpc") }
        )

        $searcher = $null
        try {
            $configDN = ([ADSI]("LDAP://RootDSE")).Properties["configurationNamingContext"][0].ToString()
            $exchangeDN = "CN=Microsoft Exchange,CN=Services,$configDN"
            $exchangeContainer = [ADSI]("LDAP://$exchangeDN")
            $searcher = New-Object System.DirectoryServices.DirectorySearcher($exchangeContainer)
        } catch {
            New-TestResult @resultParams -Result "Failed" -Details "Failed to find Exchange configuration object."
            return
        }

        $thisServer = $null
        try {
            $searcher.Filter = "(&(objectClass=msExchExchangeServer)(cn=$($env:COMPUTERNAME)))"
            $thisServer = $searcher.FindOne()
        } catch {
            New-TestResult @resultParams -Result "Failed" -Details "Failed to find Exchange Server AD object."
            return
        }

        $httpProtocol = $null
        try {
            $serverSearcher = New-Object System.DirectoryServices.DirectorySearcher($thisServer.GetDirectoryEntry())
            $serverSearcher.Filter = "(&(objectClass=msExchProtocolCfgHTTPContainer))"
            $httpProtocol = $serverSearcher.FindOne()
        } catch {
            New-TestResult @resultParams -Result "Failed" -Details "Failed to find HTTP protocol object."
            return
        }

        $vdirsInDirectory = $httpProtocol.GetDirectoryEntry().Children

        $appHostConfig = New-Object Xml
        try {
            $appHostConfig.Load($appHostConfigPath)
        } catch {
            $errorDetails = @(
                "applicationHost.config file XML could not be loaded.",
                "Path: $appHostConfigPath",
                "Error: $($_.Exception.Message)"
            )
            New-TestResult @resultParams -Result "Failed" -Details $errorDetails
            return
        }

        <#
            Validate the state of IIS objects.
        #>

        foreach ($expectedVdir in $expectedVdirs) {
            Write-Verbose "Validating vdir $($expectedVdir.DirectoryName)."
            $expectedIISObjectsPresent = @()
            $expectedIISObjectsMissing = @()
            $siteName = ($expectedVdir.DirectoryName | Select-String "\((.*)\)").Matches.Groups[1].Value
            $iisSite = $appHostConfig.LastChild."system.applicationHost".sites.GetEnumerator() | Where-Object { $_.name -eq $siteName }
            foreach ($expectedPath in $expectedVdir.Paths) {
                $iisObject = $iisSite.application | Where-Object { $_.Path -eq $expectedPath }
                if ($null -ne $iisObject) {
                    $expectedIISObjectsPresent += $expectedPath
                } else {
                    $expectedIISObjectsMissing += $expectedPath
                }
            }

            $adObject = $vdirsInDirectory | Where-Object { $_.Properties["cn"][0].ToString() -eq $expectedVdir.DirectoryName }

            if ($expectedIISObjectsPresent.Count -eq 0) {
                if ($null -ne $adObject) {
                    New-TestResult @resultParams -Result "Failed" -Details "Virtual directory `"$($expectedVdir.DirectoryName)`" exists in AD but not in IIS."
                    # Should we say to delete the AD object? What if it's PushNotifications?
                } else {
                    New-TestResult @resultParams -Result "Information" -Details "$($expectedVdir.DirectoryName) not found. This might be expected."
                    # If there are no IIS objects and no AD object, then the state is consistent.
                    # Do we know when this is expected vs when we need to run New-VirtualDirectory?
                }
            } elseif ($expectedIISObjectsMissing.Count -gt 0) {
                New-TestResult @resultParams -Result "Failed" -Details "Partial IIS objects exist for `"$($expectedVdir.DirectoryName)`"."
                $fixesPerformed = $true

                $expectedIISObjectsPresent | ForEach-Object {
                    $nodeToRemove = $appHostConfig.SelectSingleNode("/configuration/system.applicationHost/sites/site[@name = '$siteName']/application[@path = '$_']")
                    $nodeToRemove.ParentNode.RemoveChild($nodeToRemove) | Out-Null

                    if ($null -ne $adObject) {
                        New-TestResult @resultParams -Result "Warning" -Details "Only AD object is present for $($expectedVdir.DirectoryName)"
                        # Should we say to delete the AD object?
                    }
                }
            }
        }
    }

    end {
        if ($fixesPerformed) {
            $newAppHostConfig = "$PSScriptRoot\applicationHost.config"
            $appHostConfig.Save($newAppHostConfig)
            $referenceInfo =
            "Virtual directory configuration problems were found and fixed. An updated applicationHost.config file was created here:`n`n" +
            "$PSScriptRoot\applicationHost.config.`n`n" +
            "The one currently in place can be found here:`n`n" +
            "$appHostConfigPath`n`n" +
            "Rename the current one and put the updated file in place to correct these issues."

            New-TestResult @resultParams -Result "Failed" -Details @() -ReferenceInfo $referenceInfo
        }

        if ($problemsFound) {
            New-TestResult @resultParams -Result "Failed" -Details "Virtual directory problems which must be fixed manually were found."
        }
    }
}
