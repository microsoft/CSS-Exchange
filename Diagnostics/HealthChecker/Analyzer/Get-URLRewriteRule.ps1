# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
 Pulls out URL Rewrite Rules from the web.config and applicationHost.config file to return inbound and outbound rules.
.DESCRIPTION
 This is a function that is designed to pull out the URL Rewrite Rules that are set on a location of IIS.
 It extracts both inbound rules (from rewrite/rules) and outbound rules (from rewrite/outboundRules).
 Because you can set it on an individual web.config file or the parent site(s), or the ApplicationHostConfig file for the location
 We need to check all locations to properly determine what is all set.
 The ApplicationHostConfig file must be able to be converted to Xml, but the web.config file doesn't.
 The order goes like this it appears based off testing done, if overrides are allowed which by default for URL Rewrite that is true.
    1. Current IIS Location for web.config for virtual directory
    2. ApplicationHost.config file for the same location
    3. Then move up one level (Default Web Site/mapi -> Default Web Site) and repeat 1 and 2 till no more locations.
        a. If the 'clear' flag was set at any point, we stop at that location in the process.
        b. Inbound and outbound rules track the 'clear' flag independently.
    4. Then there is a global setting in the ApplicationHost.config file.
#>
function Get-URLRewriteRule {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
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
        $urlOutboundRewriteRules = @{}
        $appHostConfigLocations = $ApplicationHostConfig.configuration.Location.path
    }
    process {
        # Build combined location list: WebConfigContent keys + appHost-only locations.
        # Some IIS locations (e.g., EAS/Proxy) exist only in applicationHost.config and have
        # no web.config entry from Get-WebApplication. We still need to walk up inheritance for them.
        $allLocations = [System.Collections.Generic.List[string]]::new()
        foreach ($wcKey in $WebConfigContent.Keys) {
            $allLocations.Add($wcKey)
        }
        foreach ($appHostPath in $appHostConfigLocations) {
            if (-not [string]::IsNullOrEmpty($appHostPath) -and
                -not $WebConfigContent.ContainsKey($appHostPath)) {
                $allLocations.Add($appHostPath)
            }
        }

        foreach ($key in $allLocations) {
            Write-Verbose "Working on key: $key"
            $continue = $true
            $clearInbound = $false
            $clearOutbound = $false
            $currentKey = $key
            $urlRewriteRules.Add($key, (New-Object System.Collections.Generic.List[object]))
            $urlOutboundRewriteRules.Add($key, (New-Object System.Collections.Generic.List[object]))

            do {
                Write-Verbose "Working on currentKey: $currentKey"
                try {
                    # the Web.config is looked at first
                    [xml]$content = $WebConfigContent[$currentKey]

                    if (-not $clearInbound) {
                        $rules = $content.configuration.'system.webServer'.rewrite.rules

                        if ($null -ne $rules) {
                            $clearInbound = $null -ne $rules.clear
                            $urlRewriteRules[$key].Add($rules)
                        } else {
                            Write-Verbose "No inbound rewrite rules in the config file"
                        }
                    }

                    if (-not $clearOutbound) {
                        $outboundRules = $content.configuration.'system.webServer'.rewrite.outboundRules

                        if ($null -ne $outboundRules) {
                            $clearOutbound = $null -ne $outboundRules.clear
                            $urlOutboundRewriteRules[$key].Add($outboundRules)
                        } else {
                            Write-Verbose "No outbound rewrite rules in the config file"
                        }
                    }
                } catch {
                    Write-Verbose "Failed to convert to xml"
                    Invoke-CatchActions
                }

                if (-not $clearInbound -or -not $clearOutbound) {
                    # Now need to look at the applicationHost.config file to determine what is set at that location.
                    # need to do this because of the case sensitive query to get the xmlNode
                    Write-Verbose "Looking at the applicationHost.config file"
                    $appKey = $appHostConfigLocations | Where-Object { $_ -eq $currentKey }

                    if ($appKey.Count -eq 1) {
                        $location = $ApplicationHostConfig.SelectNodes("/configuration/location[@path = '$appKey']")

                        if ($null -ne $location) {

                            if (-not $clearInbound) {
                                $rules = $location.'system.webServer'.rewrite.rules

                                if ($null -ne $rules) {
                                    $clearInbound = $null -ne $rules.clear
                                    $urlRewriteRules[$key].Add($rules)
                                } else {
                                    Write-Verbose "No inbound rewrite rules in the applicationHost.config file"
                                }
                            }

                            if (-not $clearOutbound) {
                                $outboundRules = $location.'system.webServer'.rewrite.outboundRules

                                if ($null -ne $outboundRules) {
                                    $clearOutbound = $null -ne $outboundRules.clear
                                    $urlOutboundRewriteRules[$key].Add($outboundRules)
                                } else {
                                    Write-Verbose "No outbound rewrite rules in the applicationHost.config file"
                                }
                            }
                        } else {
                            Write-Verbose "We didn't find the location for '$appKey' in the applicationHostConfig. This shouldn't occur."
                        }
                    } else {
                        Write-Verbose "Multiple appKeys locations found for currentKey"
                    }
                }

                if ($clearInbound -and $clearOutbound) {
                    Write-Verbose "Clear was set for both inbound and outbound, don't need to know what else was set."
                    $continue = $false
                } else {
                    $index = $currentKey.LastIndexOf("/")

                    if ($index -eq -1) {
                        $continue = $false

                        if (-not $clearInbound) {
                            # look at the global configuration of the applicationHost.config file
                            $rules = $ApplicationHostConfig.configuration.'system.webServer'.rewrite.rules

                            if ($null -ne $rules) {
                                $urlRewriteRules[$key].Add($rules)
                            } else {
                                Write-Verbose "No global configuration for inbound rewrite rules."
                            }
                        }

                        if (-not $clearOutbound) {
                            $outboundRules = $ApplicationHostConfig.configuration.'system.webServer'.rewrite.outboundRules

                            if ($null -ne $outboundRules) {
                                $urlOutboundRewriteRules[$key].Add($outboundRules)
                            } else {
                                Write-Verbose "No global configuration for outbound rewrite rules."
                            }
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
        return [PSCustomObject]@{
            Inbound  = $urlRewriteRules
            Outbound = $urlOutboundRewriteRules
        }
    }
}
