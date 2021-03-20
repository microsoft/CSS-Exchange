function Confirm-VirtualDirectoryConfiguration {
    [CmdletBinding()]
    param ()

    begin {
        $problemsFound = $false
        $fixesPerformed = $false
        $appHostConfigPath = "$($env:WINDIR)\System32\inetsrv\config\applicationHost.config"
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
            # If we failed here, either Exchange is not in the forest or we can't see it.
            # Since the scope of this check is purely for vdirs, we fail silently.
            Write-Verbose $_
            return
        }

        $thisServer = $null
        try {
            $searcher.Filter = "(&(objectClass=msExchExchangeServer)(cn=$($env:COMPUTERNAME)))"
            $thisServer = $searcher.FindOne()
        } catch {
            Write-Warning "Failed to find Exchange server with name $($env:COMPUTERNAME)."
            return
        }

        Write-Verbose "Found Exchange server $($thisServer.Properties["cn"][0].ToString())."

        $httpProtocol = $null
        try {
            $serverSearcher = New-Object System.DirectoryServices.DirectorySearcher($thisServer.GetDirectoryEntry())
            $serverSearcher.Filter = "(&(objectClass=msExchProtocolCfgHTTPContainer))"
            $httpProtocol = $serverSearcher.FindOne()
        } catch {
            Write-Warning "Failed to find HTTP protocol AD object for server $($env:COMPUTERNAME)."
            Write-Warning $_
            return
        }

        $vdirsInDirectory = $httpProtocol.GetDirectoryEntry().Children

        $appHostConfig = New-Object Xml
        try {
            $appHostConfig.Load($appHostConfigPath)
        } catch {
            Write-Warning "applicationHost.config file XML could not be loaded and my be malformed."
            Write-Warning $_
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
                    Write-Warning "Virtual directory `"$($expectedVdir.DirectoryName)`" exists in AD but not in IIS."
                    # Should we say to delete the AD object? What if it's PushNotifications?
                } else {
                    # If there are no IIS objects and no AD object, then the state is consistent. Do we need to say run New-*VirtualDirectory?
                }
            } elseif ($expectedIISObjectsMissing.Count -gt 0) {
                Write-Warning "Partial IIS objects exist for `"$($expectedVdir.DirectoryName)`"."
                Write-Warning "A new applicationHost.config file will be generated with these objects cleaned up."
                $fixesPerformed = $true

                $expectedIISObjectsPresent | ForEach-Object {
                    $nodeToRemove = $appHostConfig.SelectSingleNode("/configuration/system.applicationHost/sites/site[@name = '$siteName']/application[@path = '$_']")
                    $nodeToRemove.ParentNode.RemoveChild($nodeToRemove) | Out-Null

                    if ($null -ne $adObject) {
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
            Write-Warning "Virtual directory configuration problems were found and fixed. An updated applicationHost.config"
            Write-Warning "file was created here: $PSScriptRoot\applicationHost.config. You can rename the one at"
            Write-Warning $appHostConfigPath
            Write-Warning "and put the updated file in place to correct these issues."
        }

        if ($problemsFound) {
            Write-Warning "Some virtual directory configuration problems which must be fixed manually were found."
        }
    }
}
