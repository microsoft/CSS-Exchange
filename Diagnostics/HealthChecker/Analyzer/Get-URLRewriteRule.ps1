# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
 Pulls out URL Rewrite Rules from the web.config and applicationHost.config file to return a Hashtable of those settings.
.DESCRIPTION
 This is a function that is designed to pull out the URL Rewrite Rules that are set on a location of IIS.
 Because you can set it on an individual web.config file or the parent site(s), or the ApplicationHostConfig file for the location
 We need to check all locations to properly determine what is all set.
 The ApplicationHostConfig file must be able to be converted to Xml, but the web.config file doesn't.
 The order goes like this it appears based off testing done, if overrides are allowed which by default for URL Rewrite that is true.
    1. Current IIS Location for web.config for virtual directory
    2. ApplicationHost.config file for the same location
    3. Then move up one level (Default Web Site/mapi -> Default Web Site) and repeat 1 and 2 till no more locations.
        a. If the 'clear' flag was set at any point, we stop at that location in the process.
    4. Then there is a global setting in the ApplicationHost.config file.
#>
function Get-URLRewriteRule {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlNode]$ApplicationHostConfig,

        # Key = IIS Location (Example: Default Web Site/mapi)
        # Value = web.config content
        [Parameter(Mandatory = $true)]
        [hashtable]$WebConfigContent
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $urlRewriteRules = @{}
        $appHostConfigLocations = $ApplicationHostConfig.configuration.Location.path
    }
    process {
        foreach ($key in $WebConfigContent.Keys) {
            Write-Verbose "Working on key: $key"
            $continue = $true
            $clear = $false
            $currentKey = $key
            $urlRewriteRules.Add($key, (New-Object System.Collections.Generic.List[object]))

            do {
                Write-Verbose "Working on currentKey: $currentKey"
                try {
                    # the Web.config is looked at first
                    [xml]$content = $WebConfigContent[$currentKey]
                    $rules = $content.configuration.'system.webServer'.rewrite.rules

                    if ($null -ne $rules) {
                        $clear = $null -ne $rules.clear
                        $urlRewriteRules[$key].Add($rules)
                    } else {
                        Write-Verbose "No rewrite rules in the config file"
                    }
                } catch {
                    Write-Verbose "Failed to convert to xml"
                    Invoke-CatchActions
                }

                if (-not $clear) {
                    # Now need to look at the applicationHost.config file to determine what is set at that location.
                    # need to do this because of the case sensitive query to get the xmlNode
                    Write-Verbose "clear not set on config. Looking at the applicationHost.config file"
                    $appKey = $appHostConfigLocations | Where-Object { $_ -eq $currentKey }

                    if ($appKey.Count -eq 1) {
                        $location = $ApplicationHostConfig.SelectNodes("/configuration/location[@path = '$appKey']")

                        if ($null -ne $location) {
                            $rules = $location.'system.webServer'.rewrite.rules

                            if ($null -ne $rules) {
                                $clear = $null -ne $rules.clear
                                $urlRewriteRules[$key].Add($rules)
                            } else {
                                Write-Verbose 'No rewrite rules in the applicationHost.config file'
                            }
                        } else {
                            Write-Verbose "We didn't find the location for '$appKey' in the applicationHostConfig. This shouldn't occur."
                        }
                    } else {
                        Write-Verbose "Multiple appKeys locations found for currentKey"
                    }
                }

                if ($clear) {
                    Write-Verbose "Clear was set, don't need to know what else was set."
                    $continue = $false
                } else {
                    $index = $currentKey.LastIndexOf("/")

                    if ($index -eq -1) {
                        $continue = $false
                        # look at the global configuration of the applicationHost.config file
                        $rules = $ApplicationHostConfig.configuration.'system.webServer'.rewrite.rules

                        if ($null -ne $rules) {
                            $urlRewriteRules[$key].Add($rules)
                        } else {
                            Write-Verbose "No global configuration for rewrite rules."
                        }
                    } else {
                        $currentKey = $currentKey.Substring(0, $index)
                    }
                }
            } while ($continue)

            Write-Verbose "Completed key: $key"
        }
    }
    end {
        return $urlRewriteRules
    }
}
