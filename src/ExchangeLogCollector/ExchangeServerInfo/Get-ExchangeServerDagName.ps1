Function Get-ExchangeServerDAGName {
    param(
        [string]$Server 
    )
    Write-ScriptDebug("Function Enter: Get-ExchangeServerDAGName")
    Write-ScriptDebug("Passed: [string]Server: {0}" -f $Server)
    $oldErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Stop"
    try {
        $dagName = (Get-MailboxServer $Server -ErrorAction Stop).DatabaseAvailabilityGroup.Name 
        Write-ScriptDebug("Returning dagName: {0}" -f $dagName)
        Write-ScriptDebug("Function Exit: Get-ExchangeServerDAGName")
        return $dagName
    } catch {
        Write-ScriptHost -WriteString ("Looks like this server {0} isn't a Mailbox Server. Unable to get DAG Infomration." -f $Server) -ShowServer $false 
        return $null 
    } finally {
        $ErrorActionPreference = $oldErrorAction 
    }
}