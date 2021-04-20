#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/ComputerInformation/Get-ServerOperatingSystemVersion/Get-ServerOperatingSystemVersion.ps1
#v21.01.22.2234
Function Get-ServerOperatingSystemVersion {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '', Justification = 'Need it for old legacy servers')]
    [CmdletBinding()]
    [OutputType("System.String")]
    param(
        [string]$OsCaption
    )
    #Function Version #v21.01.22.2234

    if ($OsCaption -eq [string]::Empty -or
        $null -eq $OsCaption) {
        Write-VerboseWriter("Getting the local machine version build number")
        $OsCaption = (Get-WmiObject -Class Win32_OperatingSystem).Caption
        Write-VerboseWriter("Got '{0}' for the caption" -f $OsCaption)
    } else {
        Write-VerboseWriter("Passed - [string]OsCaption : {0}" -f $OsCaption)
    }

    $osReturnValue = [string]::Empty

    switch -Wildcard ($OsCaption) {
        "*Server 2008 R2*" { $osReturnValue = "Windows2008R2"; break }
        "*Server 2008*" { $osReturnValue = "Windows2008" }
        "*Server 2012 R2*" { $osReturnValue = "Windows2012R2"; break }
        "*Server 2012*" { $osReturnValue = "Windows2012" }
        "*Server 2016*" { $osReturnValue = "Windows2016" }
        "*Server 2019*" { $osReturnValue = "Windows2019" }
        "Microsoft Windows Server Standard" { $osReturnValue = "WindowsCore" }
        "Microsoft Windows Server Datacenter" { $osReturnValue = "WindowsCore" }
        default { $osReturnValue = "Unknown" }
    }

    Write-VerboseWriter("Returned: {0}" -f $osReturnValue)
    return [string]$osReturnValue
}
