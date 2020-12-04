#Master Template: https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Invoke-RegistryGetValue/Invoke-RegistryGetValue.ps1
Function Invoke-RegistryGetValue {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$false)][string]$RegistryHive = "LocalMachine",
    [Parameter(Mandatory=$true)][string]$MachineName,
    [Parameter(Mandatory=$true)][string]$SubKey,
    [Parameter(Mandatory=$false)][string]$GetValue,
    [Parameter(Mandatory=$false)][bool]$ReturnAfterOpenSubKey,
    [Parameter(Mandatory=$false)][object]$DefaultValue,
    [Parameter(Mandatory=$false)][scriptblock]$CatchActionFunction
    )

    #Function Version 1.2
    <#
    Required Functions:
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
    #>
    Write-VerboseWriter("Calling: Invoke-RegistryGetValue")
    try
    {
        Write-VerboseWriter("Attempting to open the Base Key '{0}' on Server '{1}'" -f $RegistryHive, $MachineName)
        $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegistryHive, $MachineName)
        Write-VerboseWriter("Attempting to open the Sub Key '{0}'" -f $SubKey)
        $RegKey= $Reg.OpenSubKey($SubKey)

        if ($ReturnAfterOpenSubKey)
        {
            Write-VerboseWriter("Returning OpenSubKey")
            return $RegKey
        }

        Write-VerboseWriter("Attempting to get the value '{0}'" -f $GetValue)
        $returnGetValue = $RegKey.GetValue($GetValue)

        if ($null -eq $returnGetValue -and
            $null -ne $DefaultValue)
        {
            Write-VerboseWriter("No value found in the registry. Setting to default value: {0}" -f $DefaultValue)
            $returnGetValue = $DefaultValue
        }

        Write-VerboseWriter("Exiting: Invoke-RegistryHandler | Returning: {0}" -f $returnGetValue)
        return $returnGetValue
    }
    catch
    {
        if ($CatchActionFunction -ne $null)
        {
            & $CatchActionFunction
        }

        Write-VerboseWriter("Failed to open the registry")
    }
    
}