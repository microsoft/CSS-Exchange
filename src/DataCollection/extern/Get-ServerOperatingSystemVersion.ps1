#Master Template: https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Get-ServerOperatingSystemVersion/Get-ServerOperatingSystemVersion.ps1
Function Get-ServerOperatingSystemVersion {
    [CmdletBinding()]
    param(
    [string]$OsCaption
    )
    
    #Function Version 1.5
    <#
    Required Functions: 
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
    #>
    
    if($OsCaption -eq [string]::Empty -or
        $OsCaption -eq $null)
    {
        Write-VerboseWriter("Getting the local machine version build number")
        $OsCaption = (Get-WmiObject -Class Win32_OperatingSystem).Caption
        Write-VerboseWriter("Got '{0}' for the caption" -f $OsCaption)
    }
    else 
    {
        Write-VerboseWriter("Passed - [string]OsCaption : {0}" -f $OsCaption)
    }
    
    $osReturnValue = [string]::Empty

    switch -Wildcard ($OsCaption)
    {
        "*Server 2008 R2*" {$osReturnValue = "Windows2008R2"; break}
        "*Server 2008*" {$osReturnValue = "Windows2008"}
        "*Server 2012 R2*" {$osReturnValue = "Windows2012R2"; break}
        "*Server 2012*" {$osReturnValue = "Windows2012"}
        "*Server 2016*" {$osReturnValue = "Windows2016"}
        "*Server 2019*" {$osReturnValue = "Windows2019"}
        "Microsoft Windows Server Standard" {$osReturnValue = "WindowsCore"}
        "Microsoft Windows Server Datacenter" {$osReturnValue = "WindowsCore"}
        default {$osReturnValue = "Unknown"}
    }
    
    Write-VerboseWriter("Returned: {0}" -f $osReturnValue)
    return [string]$osReturnValue

}