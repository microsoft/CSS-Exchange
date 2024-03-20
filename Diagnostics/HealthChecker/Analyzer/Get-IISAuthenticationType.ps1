# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-IISAuthenticationType {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlNode]$ApplicationHostConfig
    )
    begin {

        function GetAuthTypeName {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)]
                [string]$AuthType,

                [object]$CurrentAuthLocation,

                [Parameter(Mandatory = $true)]
                [string]$MainLocation,

                [Parameter(Mandatory = $true)]
                [ref]$Completed
            )
            begin {
                $Completed.Value = $false
                $CurrentAuthLocation = $CurrentAuthLocation.$AuthType
                $returnValue = [string]::Empty
            }
            process {
                if ($null -ne $CurrentAuthLocation -and
                    $null -ne $CurrentAuthLocation.enabled) {
                    # Found setting here, set to completed
                    $Completed.Value = $true

                    if ($CurrentAuthLocation.enabled -eq "false") {
                        Write-Verbose "Disabled auth type."
                        return
                    }

                    # evaluate auth types to add to list of enabled.
                    if ($AuthType -eq "anonymousAuthentication") {
                        # provided 'anonymous (default setting)' for the locations that are expected.
                        # API, Autodiscover, ecp, ews, OWA (BE), Default Web Site, Exchange Back End
                        # use MainLocation because that is the location we are evaluating
                        if ($MainLocation -like "*/API" -or
                            $MainLocation -like "*/Autodiscover" -or
                            $MainLocation -like "*/ecp" -or
                            $MainLocation -like "*/EWS" -or
                            $MainLocation -eq "Exchange Back End/OWA" -or
                            $MainLocation -eq "Default Web Site" -or
                            $MainLocation -eq "Exchange Back End") {
                            $returnValue = "anonymous (default setting)"
                        } else {
                            $returnValue = "anonymous (NOT default setting)"
                        }
                    } elseif ($AuthType -eq "windowsAuthentication") {
                        # If clear is set, we only use the value here
                        # If clear is set, we add to the default location of provider types.

                        if ($null -ne $CurrentAuthLocation.providers.clear -or
                            $null -eq $defaultWindowsAuthProviders -or
                            $defaultWindowsAuthProviders.Count -eq 0) {

                            if ($null -ne $CurrentAuthLocation.providers.add.value) {
                                $returnValue = "Windows ($($CurrentAuthLocation.providers.add.value -join ","))"
                            } else {
                                $returnValue = "Windows (No providers)" # This could be a problem??
                            }
                        } else {
                            $localAuthProviders = @($defaultWindowsAuthProviders)

                            if ($null -ne $CurrentAuthLocation.providers.add.value) {
                                $localAuthProviders += $CurrentAuthLocation.providers.add.value
                            }

                            $returnValue = "Windows ($($localAuthProviders -join ","))"
                        }
                    } else {
                        $returnValue = $AuthType.Replace("Authentication", "").Replace("ClientCertificateMapping", "Cert")
                    }
                } else {
                    # If not set here, we need to look at the parent
                    Write-Verbose "Not set at current location. Need to look at parent."
                }
            } end {
                if (-not ([string]::IsNullOrEmpty($returnValue))) { Write-Verbose "Value Set: $returnValue" }

                return $returnValue
            }
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $getIisAuthenticationType = @{}
        $appHostConfigLocations = $ApplicationHostConfig.configuration.Location.path | Where-Object { $_ -ne "" }
        $defaultWindowsAuthProviders = @($ApplicationHostConfig.configuration.'system.webServer'.security.authentication.windowsAuthentication.providers.add.value)
        $authenticationTypes = @("windowsAuthentication", "anonymousAuthentication", "digestAuthentication", "basicAuthentication",
            "clientCertificateMappingAuthentication", "iisClientCertificateMappingAuthentication")
        $failedKey = "FailedLocations"
        $getIisAuthenticationType.Add($failedKey, (New-Object System.Collections.Generic.List[object]))
    }
    process {
        # foreach each location, we need to look for each $authenticationTypes up the stack ordering to determine if it is enabled or not.
        # for this configuration type, clear flag doesn't appear to be used at all.
        foreach ($appKey in $appHostConfigLocations) {
            Write-Verbose "Working on appKey: $appKey"

            if (-not ($getIisAuthenticationType.ContainsKey($appKey))) {
                $getIisAuthenticationType.Add($appKey, [string]::Empty)
            }

            $currentKey = $appKey
            $authentication = @()
            $continue = $true
            $authenticationTypeCompleted = @{}
            $authenticationTypes | ForEach-Object { $authenticationTypeCompleted.Add($_, $false) }

            do {
                # to avoid doing a lot of loops, evaluate each location for all the authentication types before moving up a level.
                Write-Verbose "Working on currentKey: $currentKey"
                $location = $ApplicationHostConfig.SelectNodes("/configuration/location[@path = '$currentKey']")

                if ($null -ne $location -and
                    $null -ne $location.path) {
                    $authLocation = $location.'system.webServer'.security.authentication

                    if ($null -ne $authLocation) {
                        # look over each auth type
                        foreach ($authenticationType in $authenticationTypes) {
                            if ($authenticationTypeCompleted[$authenticationType]) {
                                # we already have this auth type evaluated don't use this setting here.
                                continue
                            }

                            Write-Verbose "Evaluating current authenticationType: $authenticationType"
                            $didComplete = $false
                            $params = @{
                                AuthType            = $authenticationType
                                CurrentAuthLocation = $authLocation
                                MainLocation        = $appKey
                                Completed           = [ref]$didComplete
                            }

                            $value = GetAuthTypeName @params
                            if ($didComplete) {
                                $authenticationTypeCompleted[$authenticationType] = $true

                                if (-not ([string]::IsNullOrEmpty($value))) {
                                    $authentication += $value
                                }
                            }
                        }
                        $continue = $null -ne ($authenticationTypeCompleted.Values | Where-Object { $_ -eq $false })

                        if ($continue) {
                            $index = $currentKey.LastIndexOf("/")

                            if ($index -eq -1) {
                                $continue = $false
                                $defaultAuthLocation = $ApplicationHostConfig.configuration.'system.webServer'.security.authentication

                                foreach ($authenticationType in $authenticationTypes) {
                                    if ($authenticationTypeCompleted[$authenticationType]) {
                                        # we already have this auth type evaluated don't use this setting here.
                                        continue
                                    }

                                    Write-Verbose "Evaluating global current authenticationType: $authenticationType"
                                    $didComplete = $false
                                    $params = @{
                                        AuthType            = $authenticationType
                                        CurrentAuthLocation = $defaultAuthLocation
                                        MainLocation        = $appKey
                                        Completed           = [ref]$didComplete
                                    }

                                    $value = GetAuthTypeName @params
                                    if ($didComplete) {
                                        $authenticationTypeCompleted[$authenticationType] = $true

                                        if (-not ([string]::IsNullOrEmpty($value))) {
                                            $authentication += $value
                                        }
                                    }
                                }
                            } else {
                                $currentKey = $currentKey.Substring(0, $index)
                            }
                        }
                    } else {
                        Write-Verbose "authLocation was NULL, but shouldn't be a problem we just use the parent."
                        $index = $currentKey.LastIndexOf("/")

                        if ($index -eq -1) {
                            $continue = $false
                            Write-Verbose "No parent location. Need to determine how to address."
                            $getIisAuthenticationType[$failedKey].Add($appKey)
                        } else {
                            $currentKey = $currentKey.Substring(0, $index)
                        }
                    }
                } elseif ($currentKey -ne $appKey) {
                    # If we are at a parent location we might not have all the locations in the config. So this could be okay.
                    Write-Verbose "Couldn't find location for '$currentKey'. Keep on looking"
                    $index = $currentKey.LastIndexOf("/")

                    if ($index -eq -1) {
                        Write-Verbose "Didn't have root parent in the config file, this is odd."
                        $getIisAuthenticationType[$failedKey].Add($appKey)
                        $continue = $false
                    } else {
                        $currentKey = $currentKey.Substring(0, $index)
                    }
                } else {
                    Write-Verbose "Couldn't find location. This shouldn't occur."
                    # Add to failed key to display issue
                    $getIisAuthenticationType[$failedKey].Add($appKey)
                }
            } while ($continue)

            $getIisAuthenticationType[$appKey] = $authentication
            Write-Verbose "Found auth types for enabled for '$appKey': $($authentication -join ",")"
        }
    }
    end {
        return $getIisAuthenticationType
    }
}
