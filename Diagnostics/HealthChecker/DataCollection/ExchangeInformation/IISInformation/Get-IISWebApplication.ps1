# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-IISWebApplication {
    $webApplications = Get-WebApplication
    $returnList = New-Object 'System.Collections.Generic.List[object]'

    foreach ($webApplication in $webApplications) {
        try {
            $linkedConfigurationLine = $null
            $webConfigContent = $null
            $linkedConfigurationFilePath = $null
            $validWebConfig = $false # able to convert the file to xml type
            # set back to default, just incase there is an exception below
            $webConfigExists = $false
            $configurationFilePath = [string]::Empty
            $siteName = $webApplication.ItemXPath | Select-String -Pattern "site\[\@name='(.+)'\s|\]"
            $friendlyName = "$($siteName.Matches.Groups[1].Value)$($webApplication.Path)"
            $configurationFilePath = (Get-WebConfigFile "IIS:\Sites\$friendlyName").FullName
            $webConfigExists = Test-Path $configurationFilePath

            if ($webConfigExists) {
                $webConfigContent = Get-Content $configurationFilePath -Raw

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

        $returnList.Add([PSCustomObject]@{
                FriendlyName               = $friendlyName
                Path                       = $webApplication.Path
                ConfigurationFileInfo      = ([PSCustomObject]@{
                        Valid                       = $validWebConfig
                        Location                    = $configurationFilePath
                        Content                     = $webConfigContent
                        Exist                       = $webConfigExists
                        LinkedConfigurationLine     = $linkedConfigurationLine
                        LinkedConfigurationFilePath = $linkedConfigurationFilePath
                    })
                ApplicationPool            = $webApplication.applicationPool
                EnabledProtocols           = $webApplication.enabledProtocols
                ServiceAutoStartEnabled    = $webApplication.serviceAutoStartEnabled
                ServiceAutoStartProvider   = $webApplication.serviceAutoStartProvider
                PreloadEnabled             = $webApplication.preloadEnabled
                PreviouslyEnabledProtocols = $webApplication.previouslyEnabledProtocols
                ServiceAutoStartMode       = $webApplication.serviceAutoStartMode
                VirtualDirectoryDefaults   = $webApplication.virtualDirectoryDefaults
                Collection                 = $webApplication.Collection
                Location                   = $webApplication.Location
                ItemXPath                  = $webApplication.ItemXPath
                PhysicalPath               = $webApplication.PhysicalPath.Replace("%windir%", $env:windir).Replace("%SystemDrive%", $env:SystemDrive)
            })
    }

    return $returnList
}
