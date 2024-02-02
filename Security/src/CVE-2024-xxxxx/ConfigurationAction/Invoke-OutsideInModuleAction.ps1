# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Get-RemoteRegistryValue.ps1

function Invoke-OutsideInModuleAction {
    [CmdletBinding(DefaultParameterSetName = "ConfigureOutsideIn", ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ConfigureOutsideIn")]
        [Parameter(Mandatory = $true, ParameterSetName = "ConfigureFileTypes")]
        [ValidateSet("ConfigureOutsideIn", "ConfigureFileTypes", "OutsideInVersionOverride", "FileTypesOverride")]
        [string]$Configuration,

        [Parameter(Mandatory = $true, ParameterSetName = "ConfigureFileTypes")]
        [object]$FileTypesDictionary,

        [Parameter(Mandatory = $true, ParameterSetName = "ConfigureOutsideIn")]
        [Parameter(Mandatory = $true, ParameterSetName = "ConfigureFileTypes")]
        [ValidateSet("Allow", "Block")]
        [string]$Action
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        function GetFipFsConfigurationPath {
            param(
                [string]$MachineName = $env:COMPUTERNAME
            )

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"

            $fipFsDatabaseParams = @{
                MachineName = $MachineName
                SubKey      = "SOFTWARE\Microsoft\ExchangeServer\v15\FIP-FS"
                GetValue    = "DatabasePath"
            }

            Write-Verbose "Trying to detect FIP-FS database path for machine: $MachineName"
            $fipFsDatabasePath = Get-RemoteRegistryValue @fipFsDatabaseParams

            if (-not[System.String]::IsNullOrWhiteSpace($fipFsDatabasePath)) {
                Write-Verbose "FIP-FS database path is: $fipFsDatabasePath"
                return (Join-Path $fipFsDatabasePath "Configuration.xml")
            } else {
                Write-Verbose "Unable to read FIP-FS database path from registry"
                return $null
            }
        }

        function BackupFipFsConfiguration {
            param(
                [string]$FipFsConfigurationPath
            )

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"
            $returnObject = @{
                BackupSuccessful = $false
                BackupFilePath   = $null
            }
            $backupTimestamp = Get-Date -Format yyyyMMddhhmmss

            if (Test-Path -Path $FipFsConfigurationPath) {
                Write-Verbose "FIP-FS configuration file detected"
                $configurationBackupPath = $FipFsConfigurationPath + ".$backupTimestamp" + ".bak"
                Copy-Item -Path $FipFsConfigurationPath -Destination $configurationBackupPath

                Write-Verbose "Backup configuration is: $configurationBackupPath"
                $returnObject.BackupFilePath = $configurationBackupPath
                $returnObject.BackupSuccessful = $true
            } else {
                Write-Verbose "FIP-FS configuration file doesn't exist"
            }

            return $returnObject
        }

        function StartStopFipFsDependentServices {
            param(
                [ValidateSet("Start", "Stop")]
                [string]$ServiceAction
            )

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"
            try {
                if ($ServiceAction -eq "Stop") {
                    Write-Verbose "Stopping MSExchangeTransport and FMS services..."
                    Stop-Service -Name "FMS" -Force
                } else {
                    Write-Verbose "Starting MSExchangeTransport and FMS services..."
                    Start-Service -Name "MSExchangeTransport"
                    Start-Service -Name "FMS"
                }
            } catch {
                Write-Verbose "We hit an exception while performing services action: $ServiceAction"
                Write-Verbose "Exception: $_"

                return $false
            }

            return $true
        }

        function MoveFileTypesBetweenNodes {
            param(
                [object]$Element,

                [string]$FileType,

                [ValidateSet("Text", "Excel", "PreferIFilters", "IFiltersOnly", "PreferOutsideIn", "OutsideInOnly")]
                [string]$TargetFileTypeList,

                [switch]$RestoreFileTypeList
            )

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"

            # Mapping of the file types specified in the configuration.xml to the corresponding module list
            $fileTypesModuleMapping = @{
                "Text"              = "Text"
                "XlsbOfficePackage" = "Excel"
                "XlsmOfficePackage" = "Excel"
                "XlsxOfficePackage" = "Excel"
                "ExcelStorage"      = "Excel"
                "DocmOfficePackage" = "PreferIFilters"
                "DocxOfficePackage" = "PreferIFilters"
                "PptmOfficePackage" = "PreferIFilters"
                "PptxOfficePackage" = "PreferIFilters"
                "WordStorage"       = "PreferIFilters"
                "PowerPointStorage" = "PreferIFilters"
                "VisioStorage"      = "PreferIFilters"
                "Rtf"               = "PreferIFilters"
                "Xml"               = "PreferIFilters"
                "OdfTextDocument"   = "PreferIFilters"
                "OdfSpreadsheet"    = "PreferIFilters"
                "OdfPresentation"   = "PreferIFilters"
                "OneNote"           = "PreferIFilters"
                "VsdmOfficePackage" = "IFiltersOnly"
                "VsdxOfficePackage" = "IFiltersOnly"
                "VssmOfficePackage" = "IFiltersOnly"
                "VssxOfficePackage" = "IFiltersOnly"
                "VstmOfficePackage" = "IFiltersOnly"
                "VstxOfficePackage" = "IFiltersOnly"
                "VisioXml"          = "IFiltersOnly"
                "PublisherStorage"  = "IFiltersOnly"
                "Html"              = "PreferOutsideIn"
                "Pdf"               = "PreferOutsideIn"
                "AutoCad"           = "OutsideInOnly"
                "Jpeg"              = "OutsideInOnly"
                "Tiff"              = "OutsideInOnly"
            }

            # Clone a node so that we could reuse it to add file types back
            $nodeCloneTemplate = ($Element.Node | Where-Object { $null -ne $_.Type } | Select-Object -First 1).CloneNode($true)

            if ($null -eq $nodeCloneTemplate) {
                Write-Verbose "Fail to clone a file type node - function cannot continue"
                return $false
            }

            if (-not($RestoreFileTypeList)) {
                Write-Verbose "Function will move file type: $FileType to file type list: $TargetFileTypeList"

                # Get the target node to which the file type should be moved
                $targetNode = $Element.node | Where-Object { $_.Name -eq $TargetFileTypeList }

                if ($null -ne $targetNode) {

                    # Remove the file type from its current file type list
                    $Element.Node.Type | Where-Object {
                        $_.Name.StartsWith("$FileType", "CurrentCultureIgnoreCase")
                    } | ForEach-Object {
                        Write-Verbose "FileType: $FileType will be removed from the $($Element.Node.Name) file type list"
                        [void]($_.ParentNode.RemoveChild($_))
                    }

                    # Add the file type to the file type list that was passed to the function via TargetFileTypeList parameter
                    Write-Verbose "FileType: $FileType will be added to the allow list: $TargetFileTypeList"
                    $nodeClone = $nodeCloneTemplate.Type.CloneNode($true)
                    $nodeClone.Name = "$FileType"
                    [void]$targetNode.AppendChild($nodeClone)
                } else {
                    Write-Verbose "Target file type list wasn't found and as a result, the function can't continue"
                }
            } else {

                Write-Verbose "Restoring the original file type to file type list mapping"

                # Process each file type list node
                foreach ($e in $Element) {

                    # Process each file type which is assigned to the file type list
                    foreach ($type in $e.Node.Type.Name) {

                        $moveToFileTypeList = [string]::Empty
                        $fileTypeSearchString = $type
                        $i = $type.IndexOf("|NO")

                        if ($i -ne -1) {
                            Write-Verbose "File type: $type has an override flag assigned which will be removed"
                            # Remove the "|NO" override flag for all file types
                            $resetTypeOverride = @{
                                Element  = $e.Node
                                Type     = "Type"
                                TypeName = $type
                                Action   = "Remove"
                            }

                            SetConfigurationOverride @resetTypeOverride

                            $fileTypeSearchString = $type.Replace("|NO", "")
                        }

                        # Find the file type list in the mapping table and skip it, if we don't find it in the list
                        $moveToFileTypeList = $fileTypesModuleMapping["$fileTypeSearchString"]
                        $targetFileTypeListNode = $Element.Node | Where-Object { $_.Name -eq $moveToFileTypeList }

                        if ([string]::IsNullOrEmpty($moveToFileTypeList)) {
                            Write-Verbose "No mapping exists for file type: $fileTypeSearchString - this file type will be skipped"
                            continue
                        }

                        # If the file type is already in the original file type list, no further action is required - skip it too
                        if (($Element.Node | Where-Object { $_.Name -eq $moveToFileTypeList }).Type.Name -contains $fileTypeSearchString) {
                            Write-Verbose "File type: $fileTypeSearchString is already in the default file type list"
                            continue
                        }

                        # Remove the file type from its current file type list if a drift to the original mapping was detected
                        $e.Node.Type | Where-Object {
                            $_.Name.StartsWith("$fileTypeSearchString", "CurrentCultureIgnoreCase")
                        } | ForEach-Object {
                            Write-Verbose "FileType: $fileTypeSearchString will be removed from the $($e.Node.Name) file type list"
                            [void]($_.ParentNode.RemoveChild($_))
                        }

                        # Add the file type back to the original file type list based on the original mapping
                        Write-Verbose "FileType: $fileTypeSearchString will be added back to type list: $moveToFileTypeList"
                        $nodeClone = $nodeCloneTemplate.Type.CloneNode($true)
                        $nodeClone.Name = "$fileTypeSearchString"
                        [void]$targetFileTypeListNode.AppendChild($nodeClone)
                    }
                }
            }
        }

        function SetConfigurationOverride {
            [CmdletBinding(DefaultParameterSetName = "Module")]
            [OutputType([boolean])]
            param(
                [object]$Element,

                [ValidateSet("Module", "Type")]
                [string]$Type,

                [string]$TypeName,

                [ValidateSet("Add", "Remove")]
                [string]$Action
            )

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"

            # TODO: Optimize this code to remove duplicate code paths
            if ($Type -eq "Module") {
                $elementName = $Element.Module.InnerText
            } else {
                $typeObject = $Element.Type | Where-Object { $_.Name.StartsWith("$TypeName", "CurrentCultureIgnoreCase") }
                $elementName = $typeObject.Name
            }

            if ($elementName.Count -gt 1) {
                Write-Verbose "Element contains multiple modules/types which can't be processed by this function"
                return $false
            }

            if ($Type -eq "Module") {
                $index = $Element.Module.InnerText.IndexOf("|NO")
            } else {
                $index = $elementName.IndexOf("|NO")
            }

            if ($Action -eq "Add" -and
                $index -eq -1) {
                Write-Verbose "Override will be set for: $elementName"

                if ($Type -eq "Module") {
                    $Element.Module.InnerText = "$elementName|NO"
                } else {
                    $typeObject.Name = "$elementName|NO"
                }

                return $true
            } elseif ($Action -eq "Remove" -and
                $index -ne -1) {
                Write-Verbose "Override will be removed for: $elementName"

                if ($Type -eq "Module") {
                    $Element.Module.InnerText = $Element.Module.InnerText.Substring(0, $index)
                } else {
                    $typeObject.Name = $typeObject.Name.Substring(0, $index)
                }

                return $true
            } else {
                Write-Verbose "Unable to perform the override configuration. This could be because the override exists or was already removed."
            }

            return $false
        }

        function GetConfigurationOverrideInfo {
            param(
                [object[]]$Elements
            )

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"
            $returnListObject = New-Object 'System.Collections.Generic.List[object]'

            foreach ($e in $Elements) {
                $typeListListObject = New-Object 'System.Collections.Generic.List[object]'

                foreach ($type in $e.Type.Name) {
                    $name = [string]::Empty
                    $overrideFound = $false
                    $name = $type
                    $index = $name.IndexOf("|NO")

                    if ($index -eq -1) {
                        Write-Verbose "No override was detected for $type"
                    } else {
                        Write-Verbose "Override was detected for $type"
                        $overrideFound = $true
                    }

                    $typeListListObject.Add([PSCustomObject]@{
                            Name           = $type
                            OverrideExists = $overrideFound
                            StartIndex     = $index
                        })
                }

                $elementReturnObject = [PSCustomObject]@{
                    TypeList = $e.Name
                    Types    = $typeListListObject
                }

                $returnListObject.Add($elementReturnObject)
            }

            return $returnListObject
        }

        function SetConfigurationAttribute {
            [CmdletBinding(DefaultParameterSetName = "ConfigureOutsideIn", SupportsShouldProcess = $true, ConfirmImpact = 'High')]
            param(
                [object[]]$Nodes,

                [ValidateSet("ConfigureOutsideIn", "ConfigureFileTypes", "ConfigureOutsideInOverride", "ConfigureFileTypeOverride")]
                [string]$ConfigurationMode = "ConfigureOutsideIn",

                [object]$FileTypes,

                [string]$ModuleToConfigure = "OutsideInModule.dll",

                [bool]$Enabled = $false
            )

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"

            # Configuration strings are case sensitive and must be set to lowercase true or false
            $modulesEnabledValue = if ($Enabled) { "true" } else { "false" }

            if ($ConfigurationMode -eq "ConfigureFileTypes" -or
                $ConfigurationMode -eq "ConfigureFileTypeOverride") {

                # We need to clone a node just in case that we need to add file types back to an allowed list
                $nodeCloneTemplate = ($Nodes.Node | Where-Object { $null -ne $_.Type } | Select-Object -First 1).CloneNode($true)
            }

            if ($ConfigurationMode -eq "ConfigureFileTypeOverride") {

                # We add or remove the 'NO' flag for a particular file type as this is supported with the March 2024 SU.
                # The 'NO' flag will only be considered by Exchange Server for file types which are part of the 'OutsideInOnly' type list.
                $fileTypesConfigurationOverrideInfo = GetConfigurationOverrideInfo -Elements $Nodes.Node

                if ($Enabled) {
                    foreach ($ft in $FileTypes) {

                        $fileTypeFoundInLists = $null

                        # Validate the current file type status: file type exists? 'NO' override already set?
                        $fileTypeFoundInLists = $fileTypesConfigurationOverrideInfo | Where-Object { $_.Types.Name -contains $ft }

                        if ($null -ne $fileTypeFoundInLists) {

                            if ($fileTypeFoundInLists.TypeList.Count -gt 1) {

                                Write-Verbose "File type: $ft is assigned to multiple file type lists and therefore ambiguous - it will be skipped"
                                Write-Verbose "File type lists the file type is assigned to: $([string]::Join(", ", $fileTypeFoundInLists.TypeList))"
                                continue
                            }

                            # Conditions for a working override are:
                            # Override flag must be set (e.g., XlsxOfficePackage|NO)
                            # File type must be part of the 'OutsideInOnly' type list

                            # Check if the file type is in the 'OutsideInOnly' type list and move it, if it's not
                            if ($fileTypeFoundInLists.TypeList -ne "OutsideInOnly") {

                                Write-Verbose "File type: $ft is not part of the 'OutsideInOnly' type list and needs to be moved to it"
                                MoveFileTypesBetweenNodes -Element $Nodes -FileType $ft -TargetFileTypeList OutsideInOnly
                            } else {
                                Write-Verbose "File type: $ft is already part of the 'OutsideInOnly' type list and no further action is required"
                            }

                            # Call the SetConfigurationOverride function to set the override - the function will only set if it's not yet in place
                            $enableTypeOverrideParams = @{
                                Element  = $Nodes.Node
                                Type     = "Type"
                                TypeName = $ft
                                Action   = "Add"
                            }

                            SetConfigurationOverride @enableTypeOverrideParams
                        } else {
                            Write-Verbose "File type: $ft wasn't found on any file type list"
                        }
                    }
                } else {

                    # Reset the file types by moving them back to their original file type list and removing the override flag ('NO')
                    Write-Verbose "Restoring the file type to file type list mapping and removing the override flag"
                    MoveFileTypesBetweenNodes -Element $Nodes -RestoreFileTypeList
                }
            } else {
                foreach ($n in $Nodes) {

                    $fileTypesEntry = $null

                    if ($ConfigurationMode -eq "ConfigureFileTypes") {

                        $fileTypesEntry = $FileTypes["$($n.Node.Name)"]

                        if ($Enabled -eq $false) {

                            # Remove the specified file types from the file type list if they exist
                            if ($null -ne $fileTypesEntry) {

                                Write-Verbose "AllowedType: $($n.Node.Name) found - checking for file types entries now..."
                                $n.Node.Type | Where-Object {
                                    $_.Name -in $fileTypesEntry
                                } | ForEach-Object {
                                    Write-Verbose "FileType: $($n.Node.Type) is on the allow types list and will be removed now"
                                    [void]($_.ParentNode.RemoveChild($_))
                                }
                            } else {
                                Write-Verbose "AllowedType: $($n.Node.Name) not found and will be skipped"
                            }
                        } else {

                            # Add the specified file types back to the file type list
                            if ($null -ne $fileTypesEntry) {

                                Write-Verbose "AllowedType: $($n.Node.Name) found - checking for file types entries now..."
                                $fileTypesEntry | ForEach-Object {
                                    if ($n.Node.Type.Name -notcontains $_) {
                                        Write-Verbose "FileType: $_ will be added to the allow list"
                                        $nodeClone = $nodeCloneTemplate.Type.CloneNode($true)
                                        $nodeClone.Name = "$_"
                                        [void]$n.Node.AppendChild($nodeClone)
                                    } else {
                                        Write-Verbose "FileType: $_ is already on the allow types list and will be skipped"
                                    }
                                }
                            }
                        }
                    } elseif ($ConfigurationMode -eq "ConfigureOutsideIn") {

                        # OutsideInModule will explicitly enabled or disabled (Enabled=true or Enabled=false - value is case-sensitive and must be lower case)
                        if ($n.Node.InnerText.StartsWith($ModuleToConfigure, "CurrentCultureIgnoreCase")) {
                            Write-Verbose "Setting module: $($n.Node.InnerText) to Enabled: $Enabled"
                            $n.Node.Attributes["Enabled"].Value = $modulesEnabledValue
                        } else {
                            Write-Verbose "Module: $($n.Node.InnerText) will be skipped as it's not related to: $ModuleToConfigure"
                        }
                    } elseif ($ConfigurationMode -eq "ConfigureOutsideInOverride") {

                        # The 'NO' flag for the OutsideInModule.dll in the 'OutsideInOnly' module list will be set or removed
                        $outsideInOnlyModuleList = $n.Node.ModuleList  | Where-Object { $_.TypeList -eq "OutsideInOnly" }

                        if ($null -ne $outsideInOnlyModuleList) {
                            Write-Verbose "OutsideInOnly module list found - override should be added? $Enabled"
                            $outsideInOnlyParams = @{
                                Element = $outsideInOnlyModuleList
                                Type    = "Module"
                                Action  = if ($Enabled) { "Add" } else { "Remove" }
                            }
                            SetConfigurationOverride @outsideInOnlyParams
                        }
                    }
                }
            }
        }

        function PerformFipFsConfigurationOperation {
            [CmdletBinding(DefaultParameterSetName = "ConfigureOutsideIn", ConfirmImpact = 'High')]
            param(
                [string]$FipFsConfigurationPath,

                [ValidateSet("DisableOutsideIn", "EnableOutsideIn", "BlockVulnerableFileTypes", "AllowVulnerableFileTypes", "EnableOitVersionOverride", "DisableOitVersionOverride", "EnableFileTypesOverride", "DisableFileTypesOverride")]
                [string]$Operation,

                [object]$FileTypesDictionary
            )

            begin {
                Write-Verbose "Calling: $($MyInvocation.MyCommand)"

                $configXmlNamespaces = @{
                    root = "http://schemas.microsoft.com/forefront/2010/1/fs-configuration"
                    sys  = "http://schemas.microsoft.com/forefront/2010/1/fs-systemconfiguration"
                }

                $moduleListsPath = "/root:Configuration/sys:System/sys:TextExtractionSettings/sys:ModuleLists"
                $modulePath = "/root:Configuration/sys:System/sys:TextExtractionSettings/sys:ModuleLists/sys:ModuleList/sys:Module"
                $typePath = "/root:Configuration/sys:System/sys:TextExtractionSettings/sys:TypeLists/sys:TypeList"
            } process {

                # Stopping MSExchangeTransport and FMS services
                if (StartStopFipFsDependentServices -ServiceAction "Stop") {

                    # Perform backup of the existing configuration.xml
                    $fipFsConfigurationBackup = BackupFipFsConfiguration -FipFsConfigurationPath $FipFsConfigurationPath

                    if ($fipFsConfigurationBackup.BackupSuccessful) {
                        try {
                            Write-Verbose "Operation that should be performed is: $Operation"

                            [xml]$configuration = Get-Content -Path $FipFsConfigurationPath

                            # Based on how blocking will be done, we need the corresponding path
                            if ($Operation -eq "EnableOitVersionOverride" -or
                                $Operation -eq "DisableOitVersionOverride") {

                                # We need the ModuleLists node here as override will only be considered on 'OutsideInOnly'
                                $moduleLists = $configuration | Select-Xml -Namespace $configXmlNamespaces -XPath $moduleListsPath

                                # We use this to add or remove the 'NO' flag to the 'OutsideInOnly' module list.
                                # The override will work if the March 2024 SU is installed.
                                $outsideInOverrideParams = @{
                                    Nodes             = $moduleLists
                                    ConfigurationMode = "ConfigureOutsideInOverride"
                                    Enabled           = if ( $Operation -eq "DisableOitVersionOverride") { $false } else { $true }
                                }

                                SetConfigurationAttribute @outsideInOverrideParams
                            } elseif ($Operation -eq "DisableOutsideIn" -or
                                $Operation -eq "EnableOutsideIn") {

                                # We use this to block the OutsideInModule for all module lists
                                $modules = $configuration | Select-Xml -Namespace $configXmlNamespaces -XPath $modulePath

                                # Perform the action based on the value that was passed via Operation parameter
                                $outsideInParams = @{
                                    Nodes   = $modules
                                    Enabled = if ( $Operation -eq "DisableOutsideIn") { $false } else { $true }
                                }

                                SetConfigurationAttribute @outsideInParams
                            } elseif ($Operation -eq "EnableFileTypesOverride" -or
                                $Operation -eq "DisableFileTypesOverride") {

                                # We call the function to add or remove file type overrides
                                $types = $configuration | Select-Xml -Namespace $configXmlNamespaces -XPath $typePath
                                $fileTypesOverrideParams = @{
                                    Nodes             = $types
                                    ConfigurationMode = "ConfigureFileTypeOverride"
                                    FileTypes         = $FileTypesDictionary
                                    Enabled           = if ($Operation -eq "DisableFileTypesOverride") { $false } else { $true }
                                }

                                SetConfigurationAttribute @fileTypesOverrideParams
                            } elseif ($Operation -eq "BlockVulnerableFileTypes" -or
                                $Operation -eq "AllowVulnerableFileTypes") {

                                # We use this to partially blocking the vulnerable file types
                                $types = $configuration | Select-Xml -Namespace $configXmlNamespaces -XPath $typePath
                                $fileTypeParams = @{
                                    Nodes             = $types
                                    ConfigurationMode = "ConfigureFileTypes"
                                    FileTypes         = $FileTypesDictionary
                                    Enabled           = if ($Operation -eq "BlockVulnerableFileTypes") { $false } else { $true }
                                }

                                SetConfigurationAttribute @fileTypeParams
                            }
                        } catch {
                            Write-Host "We hit an exception while processing the change to the configuration.xml. Please run the script again."
                            Write-Verbose "Exception: $_"
                        }
                    } else {
                        Write-Host "We fail to create a backup of the configuration.xml file. Please run the script again."
                    }
                } else {
                    Write-Host "We fail to stop the MSExchangeTransport and FMS services. Please run the script again."
                }
            } end {
                # Save the modified FIP-FS configuration.xml and finally, restart the MSExchangeTransport and FMS services to make them pick up the changes
                $configuration.Save($FipFsConfigurationPath)
                if (-not(StartStopFipFsDependentServices -ServiceAction "Start")) {
                    Write-Host "MSExchangeTransport and FMS services couldn't be restarted."
                    Write-Host "Please try to restart them manually and if it doesn't work, restore the following backup: $($fipFsConfigurationBackup.BackupFilePath)"
                }
            }
        }
    } end {
        $fipsOperationParams = @{
            FipFsConfigurationPath = GetFipFsConfigurationPath
        }

        if ($Configuration -eq "ConfigureFileTypes") {

            $fipsOperationParams.Add("FileTypesDictionary", $FileTypesDictionary)
            $fipsOperationParams.Add("Operation", $(if ($Action -eq "Allow") { "AllowVulnerableFileTypes" } else { "BlockVulnerableFileTypes" }))
        } elseif ($Configuration -eq "OutsideInVersionOverride") {

            $fipsOperationParams.Add("Operation", $(if ($Action -eq "Allow") { "EnableOitVersionOverride" } else { "DisableOitVersionOverride" }))
        } elseif ($Configuration -eq "FileTypesOverride") {

            if ($Action -eq "Allow" -and
                $null -ne $FileTypesDictionary) {

                # We must pass the file types here that should be allowed to use OutsideInModule
                $fipsOperationParams.Add("Operation", "EnableFileTypesOverride")
                $fipsOperationParams.Add("FileTypesDictionary", $FileTypesDictionary)
            } elseif ($Action -eq "Block") {

                # File type list will be restored and 'NO' override flags will be removed (in case they exist)
                $fipsOperationParams.Add("Operation", "DisableFileTypesOverride")
            }
        } else {

            $fipsOperationParams.Add("Operation", $(if ($Action -eq "Allow") { "EnableOutsideIn" } else { "DisableOutsideIn" }))
        }

        PerformFipFsConfigurationOperation @fipsOperationParams
    }
}
