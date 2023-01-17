# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-TestResult.ps1
. $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-OrganizationContainer.ps1

function Test-VirtualDirectoryConfiguration {
    [CmdletBinding()]
    param ()

    begin {
        $problemsFound = $false
        $fixesPerformed = $false
        $appHostConfigPath = "$($env:WINDIR)\System32\inetSrv\config\applicationHost.config"
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

        $expectedVDirs = @(
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
            $exchangeContainer = Get-ExchangeContainer
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

        if ($null -eq $httpProtocol) {
            New-TestResult @resultParams -Result "Failed" -Details "Failed to find HTTP protocol object."
            return
        }

        $VDirsInDirectory = $httpProtocol.GetDirectoryEntry().Children

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

        foreach ($expectedVDir in $expectedVDirs) {
            Write-Verbose "Validating VDir $($expectedVDir.DirectoryName)."
            $expectedIISObjectsPresent = @()
            $expectedIISObjectsMissing = @()
            $siteName = ($expectedVDir.DirectoryName | Select-String "\((.*)\)").Matches.Groups[1].Value
            $iisSite = $appHostConfig.LastChild."system.applicationHost".sites.GetEnumerator() | Where-Object { $_.name -eq $siteName }
            foreach ($expectedPath in $expectedVDir.Paths) {
                $iisObject = $iisSite.application | Where-Object { $_.Path -eq $expectedPath }
                if ($null -ne $iisObject) {
                    $expectedIISObjectsPresent += $iisObject.Path
                } else {
                    $expectedIISObjectsMissing += $expectedPath
                }
            }

            $adObject = $VDirsInDirectory | Where-Object { $_.Properties["cn"][0].ToString() -eq $expectedVDir.DirectoryName }
            $locationPaths = ($appHostConfig.LastChild.Location.GetEnumerator() |
                    Where-Object { $_.Path -like "$($iisSite.Name)$($expectedVDir.Paths[0])*" }).Path
            $customMetadataPaths = ($appHostConfig.LastChild."system.applicationHost".customMetadata.key.GetEnumerator() |
                    Where-Object { $_.Path -like "*$($iisSite.Id)/ROOT$($expectedVDir.Paths[0])*" } ).Path
            $owaRootPaths = @()

            if ($expectedVDir.DirectoryName -eq "owa (Exchange Back End)") {
                $specialPaths = @("/Exchange", "/Exchweb", "/Public")
                $tempLocationPaths = @()

                foreach ($path in $specialPaths) {
                    $node = $appHostConfig.LastChild.Location.GetEnumerator() | Where-Object { $_.Path -like "$($iisSite.Name)$path" }
                    if ($null -ne $node) { $tempLocationPaths += $node.Path }
                }

                if ($null -eq $locationPaths) {
                    $locationPaths = $tempLocationPaths
                } elseif ($tempLocationPaths.Count -gt 0) {
                    $locationPaths += $tempLocationPaths
                }

                foreach ($path in $specialPaths) {
                    $node = ($iisSite.application.GetEnumerator() | Where-Object { $_.Path -eq "/" }).GetEnumerator() |
                        Where-Object { $_.Path -eq $path }
                    if ($null -ne $node) { $owaRootPaths += $node.Path }
                }
            }

            # Only want to enter here if we don't have any IIS settings in the appHostConfig present. Otherwise, we might have something to fix.
            if ($expectedIISObjectsPresent.Count -eq 0 -and
                $null -eq $locationPaths -and
                $null -eq $customMetadataPaths -and
                $owaRootPaths.Count -eq 0 ) {
                if ($null -ne $adObject) {
                    New-TestResult @resultParams -Result "Failed" -Details "Virtual directory `"$($expectedVDir.DirectoryName)`" exists in AD but not in IIS."
                    # Should we say to delete the AD object? What if it's PushNotifications?
                } else {
                    New-TestResult @resultParams -Result "Information" -Details "$($expectedVDir.DirectoryName) not found. This might be expected."
                    # If there are no IIS objects and no AD object, then the state is consistent.
                    # Do we know when this is expected vs when we need to run New-VirtualDirectory?
                }
            } elseif ($expectedIISObjectsMissing.Count -gt 0 -or
                $null -eq $adObject) {

                # Missing some critical information from IIS or the object is removed from AD
                # need to remove from a few different locations to allow New-*VirtualDirectory to work
                if ($expectedIISObjectsMissing.Count -gt 0) {
                    New-TestResult @resultParams -Result "Failed" -Details "Partial IIS objects exist for `"$($expectedVDir.DirectoryName)`"."
                } else {
                    New-TestResult @resultParams -Result "Failed" -Details "Full IIS Object exists for `"$($expectedVDir.DirectoryName)`", but doesn't exist in AD."
                }

                if ($expectedIISObjectsMissing.Count -gt 0) {
                    $fixesPerformed = $true
                    $expectedIISObjectsPresent | ForEach-Object {
                        Write-Verbose "Removing Node for configuration site $siteName path $_"
                        $nodeToRemove = $appHostConfig.SelectSingleNode("/configuration/system.applicationHost/sites/site[@name = '$siteName']/application[@path = '$_']")
                        $nodeToRemove.ParentNode.RemoveChild($nodeToRemove) | Out-Null
                    }
                }

                if ($null -ne $locationPaths) {
                    $fixesPerformed = $true
                    $locationPaths | ForEach-Object {
                        Write-Verbose "Removing node for location at path $_"
                        $nodeToRemove = $appHostConfig.SelectSingleNode("/configuration/location[@path = '$_']")
                        $nodeToRemove.ParentNode.RemoveChild($nodeToRemove) | Out-Null
                    }
                }

                if ($null -ne $customMetadataPaths) {
                    $fixesPerformed = $true
                    $customMetadataPaths | ForEach-Object {
                        Write-Verbose "Removing node for customMetadata at path $_"
                        $nodeToRemove = $appHostConfig.SelectSingleNode("/configuration/system.applicationHost/customMetadata/key[@path = '$_']")
                        $nodeToRemove.ParentNode.RemoveChild($nodeToRemove) | Out-Null
                    }
                }

                if ($owaRootPaths.Count -gt 0) {
                    $fixesPerformed = $true
                    $owaRootPaths | ForEach-Object {
                        Write-Verbose "Removing node for special OWA / at path $_"
                        $nodeToRemove = $appHostConfig.SelectSingleNode("/configuration/system.applicationHost/sites/site[@name = '$siteName']/application[@path = '/']/virtualDirectory[@path = '$_']")
                        $nodeToRemove.ParentNode.RemoveChild($nodeToRemove) | Out-Null
                    }
                }

                if ($null -ne $adObject) {
                    New-TestResult @resultParams -Result "Warning" -Details "Only AD object is present for $($expectedVDir.DirectoryName)"
                    # Should we say to delete the AD object?
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
