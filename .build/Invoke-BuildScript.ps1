# Invoke-BuildScript.ps1 - used to build a single script from a subset of smaller script to make it easier for development
param(
    [object]$Configuration
)
<#
    Configuration Schema

    ScriptName
    ScriptUri
    ScriptVersion
    [array]FilePaths
        -Path
        -ScriptVersionName
        -LoadOrder
        -[array]ExcludedFiles
            -FileName
        -[array]SubFunctions --- NOTE: Current file must also have '#Add Sub Functions Here' to know where to break at.
            -Path
            -LoadOrder
            -[array]ExcludedFiles
                -FileName
#>

Function Get-FilesPathsToLoad {
    param(
        [string]$FilePath,
        [array]$ExcludedFiles
    )
    $loadTheseFiles = @() 

    if ($FilePath.EndsWith("\")) {
        
        $allFiles = Get-ChildItem $FilePath | Where-Object { $_.Name.EndsWith(".ps1") }

        if ($null -ne $ExcludedFiles) {
            $allFiles = $allFiles | Where-Object { !$ExcludedFiles.Contains($_.Name) }
        }

        foreach ($file in $allFiles) {
            $loadTheseFiles += $file.VersionInfo.FileName
        }
    }
    else {
        $loadTheseFiles = (Get-ChildItem $FilePath).VersionInfo.FileName
    }

    return $loadTheseFiles
}

[System.Collections.Generic.List[System.Object]]$scriptMemory = New-Object -TypeName System.Collections.Generic.List[System.Object]
[System.Collections.Generic.List[System.Object]]$loadedFiles = New-Object -TypeName System.Collections.Generic.List[System.Object]

$scriptVersion = .\Get-ScriptVersion -GitHubWebRequestUri $Configuration.ScriptUri -ScriptVersion $Configuration.ScriptVersion
$configPaths = $Configuration.FilePaths | Sort-Object LoadOrder

foreach ($fileConfigItem in $configPaths) {
    [string]$filePath = $fileConfigItem.Path
    
    $loadTheseFiles = Get-FilesPathsToLoad -FilePath $filePath -ExcludedFiles $fileConfigItem.ExcludedFiles.FileName

    foreach ($file in $loadTheseFiles) {
        if ($loadedFiles.Contains($file)) { continue }

        $getContent = Get-Content $file

        foreach ($line in $getContent) {
            if ($null -ne $fileConfigItem.SubFunctions -and
                $line.Contains("#Add Sub Functions Here")) {
                $loadSubFunctionOrder = $fileConfigItem.SubFunctions | Sort-Object LoadOrder
                foreach ($subConfigItem in $loadSubFunctionOrder) {
                    [string]$subFilePath = $subConfigItem.Path
                    $loadTheseSubFunctions = Get-FilesPathsToLoad -FilePath $subFilePath -ExcludedFiles $subConfigItem.ExcludedFiles.FileName

                    foreach ($subFile in $loadTheseSubFunctions) {
                        if ($loadedFiles.Contains($subFile)) { continue }
                        
                        $subGetContent = Get-Content $subFile

                        foreach ($subLine in $subGetContent) {
                            $scriptMemory.Add($subLine)
                        }
                        
                        $scriptMemory.Add([string]::Empty)
                        $loadedFiles.Add($subFile)
                    }
                }
            }
            $scriptMemory.Add($line)
        }

        if ($null -ne $fileConfigItem.ScriptVersionName) {
            $scriptMemory.Add(("`${0} = `"{1}.{2}.{3}`"" -f $fileConfigItem.ScriptVersionName,
                    $scriptVersion.Major,
                    $scriptVersion.Minor,
                    $scriptVersion.BuildRevision))
        }

        $scriptMemory.Add([string]::Empty)
        $loadedFiles.Add($file)
    }
}

$scriptMemory | Out-File (".\{0}.ps1" -f $Configuration.ScriptName) -Encoding utf8
$scriptMemory | Out-File (".\{0}.txt" -f $Configuration.ScriptName) -Encoding utf8
