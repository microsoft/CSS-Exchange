#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/ComputerInformation/Get-DotNetDllFileVersions/Get-DotNetDllFileVersions.ps1
#v21.01.22.2234
Function Get-DotNetDllFileVersions {
    [CmdletBinding()]
    [OutputType("System.Collections.Hashtable")]
    param(
        [string]$ComputerName,
        [array]$FileNames,
        [scriptblock]$CatchActionFunction
    )
    #Function Version #v21.01.22.2234

    Write-VerboseWriter("Calling: Get-DotNetDllFileVersions")

    Function Invoke-ScriptBlockGetItem {
        param(
            [string]$FilePath
        )
        $getItem = Get-Item $FilePath

        $returnObject = ([PSCustomObject]@{
                GetItem          = $getItem
                LastWriteTimeUtc = $getItem.LastWriteTimeUtc
                VersionInfo      = ([PSCustomObject]@{
                        FileMajorPart   = $getItem.VersionInfo.FileMajorPart
                        FileMinorPart   = $getItem.VersionInfo.FileMinorPart
                        FileBuildPart   = $getItem.VersionInfo.FileBuildPart
                        FilePrivatePart = $getItem.VersionInfo.FilePrivatePart
                    })
            })

        return $returnObject
    }

    $dotNetInstallPath = Invoke-RegistryGetValue -MachineName $ComputerName -SubKey "SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -GetValue "InstallPath" -CatchActionFunction $CatchActionFunction

    if ($dotNetInstallPath -eq [string]::Empty) {
        Write-VerboseWriter("Failed to determine .NET install path")
        return
    }

    $files = @{}
    foreach ($filename in $FileNames) {
        Write-VerboseWriter("Query .NET DLL information for machine: {0}" -f $ComputerName)
        $getItem = Invoke-ScriptBlockHandler -ComputerName $ComputerName -ScriptBlock ${Function:Invoke-ScriptBlockGetItem} -ArgumentList ("{0}\{1}" -f $dotNetInstallPath, $filename) -CatchActionFunction $CatchActionFunction
        $files.Add($filename, $getItem)
    }

    return $files
}
