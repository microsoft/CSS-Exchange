# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-IISWebSite {
    param(
        [array]$WebSitesToProcess
    )

    $returnList = New-Object 'System.Collections.Generic.List[object]'
    $webSites = New-Object 'System.Collections.Generic.List[object]'

    if ($null -eq $WebSitesToProcess) {
        $webSites.AddRange((Get-WebSite))
    } else {
        foreach ($iisWebSite in $WebSitesToProcess) {
            $webSites.Add((Get-WebSite -Name $($iisWebSite)))
        }
    }

    $bindings = Get-WebBinding

    foreach ($site in $webSites) {
        Write-Verbose "Working on Site: $($site.Name)"
        $siteBindings = $bindings |
            Where-Object { $_.ItemXPath -like "*@name='$($site.name)' and @id='$($site.id)'*" }
        # Logic should be consistent for all ways we call Get-WebConfigFile
        try {
            $configurationFilePath = (Get-WebConfigFile "IIS:\Sites\$($site.Name)").FullName
        } catch {
            $finder = "\\?\"
            if (($_.Exception.ErrorCode -eq -2147024846 -or
                    $_.Exception.ErrorCode -eq -2147024883) -and
                $_.Exception.Message.Contains($finder)) {
                $message = $_.Exception.Message
                $index = $message.IndexOf($finder) + $finder.Length
                $configurationFilePath = $message.Substring($index, ($message.IndexOf([System.Environment]::NewLine) - $index)).Trim()
                Write-Verbose "Found possible file path from exception: $configurationFilePath"
            } else {
                Write-Verbose "Unable to find possible file path based off exception: $($_.Exception)"
            }
        }

        $webConfigExists = Test-Path $configurationFilePath
        $webConfigContent = $null
        $webConfigContentXml = $null
        $validWebConfig = $false
        $customHeaderHstsObj = [PSCustomObject]@{
            enabled             = $false
            "max-age"           = 0
            includeSubDomains   = $false
            preload             = $false
            redirectHttpToHttps = $false
        }
        $customHeaderHsts = $null

        if ($webConfigExists) {
            $webConfigContent = (Get-Content $configurationFilePath -Raw).Trim()

            try {
                $webConfigContentXml = [xml]$webConfigContent
                $validWebConfig = $true
            } catch {
                # Inside of Invoke-Command, can't use Invoke-CatchActions
                Write-Verbose "Failed to convert IIS web config '$configurationFilePath' to xml. Exception: $($_.Exception)"
            }
        }

        if ($validWebConfig) {
            <#
                HSTS configuration can be done in different ways:
                Via native HSTS control that comes with IIS 10.0 Version 1709.
                See: https://learn.microsoft.com/iis/get-started/whats-new-in-iis-10-version-1709/iis-10-version-1709-hsts
                The native control stores the HSTS configuration attributes in the <hsts> element which can be found under each <site> element.
                These settings are returned when running the Get-WebSite cmdlet and there is no need to prepare the data as they are ready for use.

                Via customHeader configuration (when running IIS older than the version mentioned before where the native HSTS config is not available
                or when admins prefer to do it via customHeader as there is no requirement to do it via native HSTS control instead of using customHeader).
                HSTS via customHeader configuration are stored under httpProtocol.customHeaders element. As we get the content in the previous
                call, we can simply use these data to extract the customHeader with name Strict-Transport-Security (if exists) and can then prepare
                the data for further processing.
                The following code searches for a customHeader with name Strict-Transport-Security. If we find the header, we then extract the directive
                and return them as PSCustomObject. We're looking for the following directive: max-age, includeSubDomains, preload, redirectHttpToHttps
            #>
            $customHeaderHsts = ($webConfigContentXml.configuration.'system.webServer'.httpProtocol.customHeaders.add | Where-Object {
                ($_.name -eq "Strict-Transport-Security")
                }).value
            if ($null -ne $customHeaderHsts) {
                Write-Verbose "Hsts via custom header configuration detected"
                $customHeaderHstsObj.enabled = $true
                # Make sure to ignore the case as per RFC 6797 the directives are case-insensitive
                # We ignore any other directives as these MUST be ignored by the User Agent (UA) as per RFC 6797
                # UAs MUST ignore any STS header field containing directives, or other header field value data,
                # that does not conform to the syntax defined in this specification.
                $maxAgeIndex = $customHeaderHsts.IndexOf("max-age=", [System.StringComparison]::OrdinalIgnoreCase)
                $includeSubDomainsIndex = $customHeaderHsts.IndexOf("includeSubDomains", [System.StringComparison]::OrdinalIgnoreCase)
                $preloadIndex = $customHeaderHsts.IndexOf("preload", [System.StringComparison]::OrdinalIgnoreCase)
                $redirectHttpToHttpsIndex = $customHeaderHsts.IndexOf("redirectHttpToHttps", [System.StringComparison]::OrdinalIgnoreCase)
                if ($maxAgeIndex -ne -1) {
                    Write-Verbose "max-age directive found"
                    $maxAgeValueIndex = $customHeaderHsts.IndexOf(";", $maxAgeIndex)
                    # add 8 to find the start index after 'max-age='
                    $maxAgeIndex = $maxAgeIndex + 8

                    # subtract maxAgeIndex to get the length that we need to find the substring
                    $maxAgeValueIndex = $maxAgeValueIndex - $maxAgeIndex
                    $customHeaderHstsObj.'max-age' = $customHeaderHsts.Substring($maxAgeIndex, $maxAgeValueIndex)
                } else {
                    Write-Verbose "max-age directive not found"
                }

                if ($includeSubDomainsIndex -ne -1) {
                    Write-Verbose "includeSubDomains directive found"
                    $customHeaderHstsObj.includeSubDomains = $true
                }

                if ($preloadIndex -ne -1) {
                    Write-Verbose "preload directive found"
                    $customHeaderHstsObj.preload = $true
                }

                if ($redirectHttpToHttpsIndex -ne -1) {
                    Write-Verbose "redirectHttpToHttps directive found"
                    $customHeaderHstsObj.redirectHttpToHttps = $true
                }
            } else {
                Write-Verbose "No Hsts via custom header configuration detected"
            }
        }

        $returnList.Add([PSCustomObject]@{
                Name                       = $site.Name
                Id                         = $site.Id
                State                      = $site.State
                Bindings                   = $siteBindings
                Limits                     = $site.Limits
                LogFile                    = $site.logFile
                TraceFailedRequestsLogging = $site.traceFailedRequestsLogging
                Hsts                       = [PSCustomObject]@{
                    NativeHstsSettings  = $site.hsts
                    HstsViaCustomHeader = $customHeaderHstsObj
                }
                ApplicationDefaults        = $site.applicationDefaults
                VirtualDirectoryDefaults   = $site.virtualDirectoryDefaults
                Collection                 = $site.collection
                ApplicationPool            = $site.applicationPool
                EnabledProtocols           = $site.enabledProtocols
                PhysicalPath               = $site.physicalPath.Replace("%windir%", $env:windir).Replace("%SystemDrive%", $env:SystemDrive)
                ConfigurationFileInfo      = [PSCustomObject]@{
                    Location = $configurationFilePath
                    Content  = $webConfigContent
                    Exist    = $webConfigExists
                    Valid    = $validWebConfig
                }
            }
        )
    }
    return $returnList
}
