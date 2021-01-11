Function Get-ExchangeAppPoolsInformation {

    Write-VerboseOutput("Calling: Get-ExchangeAppPoolsInformation")

    Function Get-ExchangeAppPoolsScriptBlock {
        $windir = $env:windir
        $Script:appCmd = "{0}\system32\inetsrv\appcmd.exe" -f $windir

        $appPools = &$Script:appCmd list apppool
        $exchangeAppPools = @()
        foreach ($appPool in $appPools) {
            $startIndex = $appPool.IndexOf('"') + 1
            $appPoolName = $appPool.Substring($startIndex, ($appPool.Substring($startIndex).IndexOf('"')))
            if ($appPoolName.StartsWith("MSExchange")) {
                $exchangeAppPools += $appPoolName
            }
        }

        $exchAppPools = @{}
        foreach ($appPool in $exchangeAppPools) {
            $status = &$Script:appCmd list apppool $appPool /text:state
            $config = &$Script:appCmd list apppool $appPool /text:CLRConfigFile
            if (!([System.String]::IsNullOrEmpty($config)) -and
                (Test-Path $config)) {
                $content = Get-Content $config
            } else {
                $content = $null
            }
            $statusObj = New-Object PSCustomObject
            $statusObj | Add-Member -MemberType NoteProperty -Name "Status" -Value $status
            $statusObj | Add-Member -MemberType NoteProperty -Name "ConfigPath" -Value $config
            $statusObj | Add-Member -MemberType NoteProperty -Name "Content" -Value $content

            $exchAppPools.Add($appPool, $statusObj)
        }

        return $exchAppPools
    }
    $exchangeAppPoolsInfo = Invoke-ScriptBlockHandler -ComputerName $Script:Server -ScriptBlock ${Function:Get-ExchangeAppPoolsScriptBlock} -ScriptBlockDescription "Getting Exchange App Pool information" -CatchActionFunction ${Function:Invoke-CatchActions}
    Write-VerboseOutput("Exiting: Get-ExchangeAppPoolsInformation")
    return $exchangeAppPoolsInfo
}