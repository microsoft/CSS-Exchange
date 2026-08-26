# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\ConvertTo-PSObject.ps1

function Get-IISWebApplication {
    try {
        $webApplications = Get-WebApplication
    } catch {
        Write-Verbose "Failed to run Get-WebApplication. Inner Exception: $_"
        Invoke-CatchActions
    }

    $returnList = New-Object 'System.Collections.Generic.List[object]'

    foreach ($webApplication in $webApplications) {
        try {
            $linkedConfigurationLine = $null
            $webConfigContent = $null
            $linkedConfigurationFilePath = $null
            $validWebConfig = $false # able to convert the file to xml type
            # set back to default, just in case there is an exception below
            $webConfigExists = $false
            $configurationFilePath = [string]::Empty
            $siteName = $webApplication.ItemXPath | Select-String -Pattern "site\[\@name='(.+)'\s|\]"
            $friendlyName = "$($siteName.Matches.Groups[1].Value)$($webApplication.Path)"
            Write-Verbose "Working on Web Application: $friendlyName"
            # Logic should be consistent for all ways we call Get-WebConfigFile
            try {
                $configurationFilePath = (Get-WebConfigFile "IIS:\Sites\$friendlyName").FullName
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

            if ($webConfigExists) {
                $webConfigContent = (Get-Content $configurationFilePath -Raw -Encoding UTF8).Trim()

                try {
                    $linkedConfigurationLine = ([xml]$webConfigContent).configuration.assemblyBinding.linkedConfiguration.href
                    $validWebConfig = $true
                    if ($null -ne $linkedConfigurationLine) {
                        $linkedConfigurationFilePath = $linkedConfigurationLine.Substring("file://".Length)
                    }
                } catch {
                    Write-Verbose "Failed to convert '$configurationFilePath' to xml. Exception: $($_.Exception)"
                }
            }
        } catch {
            # Inside of Invoke-Command, can't use Invoke-CatchActions
            Write-Verbose "Failed to process additional context for: $($webApplication.ItemXPath). Exception: $($_.Exception)"
        }

        # Convert the object to prevent serialization issues
        $convertedObject = $null
        $params = @{
            ObjectToConvert     = $webApplication
            ObjectTypeToConvert = "Microsoft.IIs.PowerShell.Framework*"
            PropertiesToSkip    = @("ChildElements", "Attributes", "Schema", "ConfigurationPathType", "ElementTagName", "Methods")
        }
        try {
            ConvertTo-PSObject @params | Invoke-RemotePipelineHandler -Result ([ref]$convertedObject)
        } catch {
            Write-Verbose "Failed to convert the object. Inner Exception: $_"
            Invoke-CatchActions
        }

        if ($null -eq $convertedObject -and
            $null -ne $webApplication) {
            Write-Verbose "ConvertTo-PSObject failed to return an object. Using the default object."
            $convertedObject = $webApplication
        }

        $returnList.Add([PSCustomObject]@{
                FriendlyName               = $friendlyName
                Path                       = $convertedObject.Path
                ConfigurationFileInfo      = ([PSCustomObject]@{
                        Valid                       = $validWebConfig
                        Location                    = $configurationFilePath
                        Content                     = $webConfigContent
                        Exist                       = $webConfigExists
                        LinkedConfigurationLine     = $linkedConfigurationLine
                        LinkedConfigurationFilePath = $linkedConfigurationFilePath
                    })
                ApplicationPool            = $convertedObject.applicationPool
                EnabledProtocols           = $convertedObject.enabledProtocols
                ServiceAutoStartEnabled    = $convertedObject.serviceAutoStartEnabled
                ServiceAutoStartProvider   = $convertedObject.serviceAutoStartProvider
                PreloadEnabled             = $convertedObject.preloadEnabled
                PreviouslyEnabledProtocols = $convertedObject.previouslyEnabledProtocols
                ServiceAutoStartMode       = $convertedObject.serviceAutoStartMode
                VirtualDirectoryDefaults   = $convertedObject.virtualDirectoryDefaults
                Collection                 = $convertedObject.Collection
                Location                   = $convertedObject.Location
                ItemXPath                  = $convertedObject.ItemXPath
                PhysicalPath               = $convertedObject.PhysicalPath.Replace("%windir%", $env:windir).Replace("%SystemDrive%", $env:SystemDrive)
            })
    }

    return $returnList
}
