#Master Template: https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Get-DotNetDllFileVersions/Get-DotNetDllFileVersions.ps1
Function Get-DotNetDllFileVersions {
    [CmdletBinding()]
    param(
    [string]$ComputerName,
    [array]$FileNames,
    [scriptblock]$CatchActionFunction
    )

    #Function Version 1.1
    <#
    Required Functions:
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Invoke-RegistryGetValue/Invoke-RegistryGetValue.ps1
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Invoke-ScriptBlockHandler/Invoke-ScriptBlockHandler.ps1
    #>

    Write-VerboseWriter("Calling: Get-DotNetDllFileVersions")

    Function ScriptBlock-GetItem{
    param(
    [string]$FilePath
    )
        $getItem = Get-Item $FilePath

        $returnObject = ([PSCustomObject]@{
            GetItem = $getItem
            LastWriteTimeUtc = $getItem.LastWriteTimeUtc
            VersionInfo = ([PSCustomObject]@{
                FileMajorPart = $getItem.VersionInfo.FileMajorPart
                FileMinorPart = $getItem.VersionInfo.FileMinorPart
                FileBuildPart = $getItem.VersionInfo.FileBuildPart
                FilePrivatePart = $getItem.VersionInfo.FilePrivatePart
            })
        })

        return $returnObject
    }

    $dotNetInstallPath = Invoke-RegistryGetValue -MachineName $ComputerName -SubKey "SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -GetValue "InstallPath" -CatchActionFunction $CatchActionFunction

    if ($dotNetInstallPath -eq [string]::Empty)
    {
        Write-VerboseWriter("Failed to determine .NET install path")
        return
    }

    $files = @{}
    foreach($filename in $FileNames)
    {
        Write-VerboseWriter("Query .NET DLL information for machine: {0}" -f $ComputerName)
        $getItem = Invoke-ScriptBlockHandler -ComputerName $ComputerName -ScriptBlock ${Function:ScriptBlock-GetItem} -ArgumentList ("{0}\{1}" -f $dotNetInstallPath, $filename) -CatchActionFunction $CatchActionFunction
        $files.Add($filename, $getItem)
    }

    return $files
}