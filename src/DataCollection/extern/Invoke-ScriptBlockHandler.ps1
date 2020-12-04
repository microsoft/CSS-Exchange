#Master Template: https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Invoke-ScriptBlockHandler/Invoke-ScriptBlockHandler.ps1
Function Invoke-ScriptBlockHandler {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true)][string]$ComputerName,
    [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
    [Parameter(Mandatory=$false)][string]$ScriptBlockDescription,
    [Parameter(Mandatory=$false)][object]$ArgumentList,
    [Parameter(Mandatory=$false)][bool]$IncludeNoProxyServerOption = $true, #Default in HealthChecker
    [Parameter(Mandatory=$false)][scriptblock]$CatchActionFunction
    )
    #Function Version 1.1
    <# 
    Required Functions: 
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
    #>
    Write-VerboseWriter("Calling: Invoke-ScriptBlockHandler")
    if(![string]::IsNullOrEmpty($ScriptBlockDescription))
    {
        Write-VerboseWriter($ScriptBlockDescription)
    }
    try 
    {
        if($ComputerName -ne $env:COMPUTERNAME)
        {
            $params = @{
                ComputerName = $ComputerName
                ScriptBlock = $ScriptBlock
                ErrorAction = "Stop"
            }

            if ($IncludeNoProxyServerOption)
            {
                Write-VerboseWriter("Including SessionOption")
                $params.Add("SessionOption", (New-PSSessionOption -ProxyAccessType NoProxyServer))
            }
    
            if($ArgumentList -ne $null) 
            {
                $params.Add("ArgumentList", $ArgumentList)
                Write-VerboseWriter("Running Invoke-Command with argument list.")
                
            }
            else
            {
                Write-VerboseWriter("Running Invoke-Command without argument list.")
            }
    
            $invokeReturn = Invoke-Command @params
            return $invokeReturn 
        }
        else 
        {
            if($ArgumentList -ne $null)
            {
                Write-VerboseWriter("Running Script Block locally with argument list.")
                $localReturn = & $ScriptBlock $ArgumentList 
            }
            else 
            {
                Write-VerboseWriter("Running Script Block locally without argument list.")
                $localReturn = & $ScriptBlock      
            }
            return $localReturn 
        }
    }
    catch 
    {
        Write-VerboseWriter("Failed to Invoke-ScriptBlockHandler")
        if($CatchActionFunction -ne $null)
        {
            & $CatchActionFunction 
        }
    }
}