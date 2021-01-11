Function Get-ExSetupDetails {

    Write-VerboseOutput("Calling: Get-ExSetupDetails")
    $exSetupDetails = [string]::Empty
    Function Get-ExSetupDetailsScriptBlock {
        Get-Command ExSetup | ForEach-Object { $_.FileVersionInfo }
    }

    $exSetupDetails = Invoke-ScriptBlockHandler -ComputerName $Script:Server -ScriptBlock ${Function:Get-ExSetupDetailsScriptBlock} -ScriptBlockDescription "Getting ExSetup remotely" -CatchActionFunction ${Function:Invoke-CatchActions}
    Write-VerboseOutput("Exiting: Get-ExSetupDetails")
    return $exSetupDetails
}