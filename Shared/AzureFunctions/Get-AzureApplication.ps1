. $PSScriptRoot\Invoke-GraphApiRequest.ps1

function Get-AzureApplication {
    [CmdletBinding()]
    param(
        $AccessToken,
        $AzureApplicationName,
        $GraphApiUrl
    )

    <#
        Get the Azure AD Application ID for the given Azure Application Name
        https://learn.microsoft.com/graph/api/application-list?view=graph-rest-1.0&tabs=http#request
    #>

    Write-Verbose "Calling $($MyInvocation.MyCommand)"

    $listAadApplicationParams = @{
        Query       = ("applications?`$filter=displayName eq '{0}'" -f $AzureApplicationName)
        AccessToken = $AccessToken
        GraphApiUrl = $GraphApiUrl
    }
    $listAadApplicationResponse = Invoke-GraphApiRequest @listAadApplicationParams

    if ($listAadApplicationResponse.Successful) {
        return $listAadApplicationResponse.Content
    }

    return $null
}
