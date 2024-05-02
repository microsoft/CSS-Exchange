. $PSScriptRoot\Get-AzureApplication.ps1
. $PSScriptRoot\Invoke-GraphApiRequest.ps1

function Remove-AzureApplication {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        $AccessToken,
        $AzureApplicationName,
        $GraphApiUrl
    )

    <#
        This function will delete the specified Azure AD application
        https://docs.microsoft.com/graph/api/application-delete?view=graph-rest-1.0&tabs=http
    #>

    Write-Verbose "Calling $($MyInvocation.MyCommand)"

    $getAadApplicationParams = @{
        AccessToken          = $AccessToken
        AzureApplicationName = $AzureApplicationName
        GraphApiUrl          = $GraphApiUrl
    }
    $getAadApplicationResponse = Get-AzureApplication @getAadApplicationParams

    if ($null -eq $getAadApplicationResponse) {
        Write-Host "Something went wrong while querying the Azure AD Application" -ForegroundColor Red
        exit
    } elseif ([System.String]::IsNullOrEmpty($getAadApplicationResponse.Value.id)) {
        Write-Host "No application with name: $AzureApplicationName found" -ForegroundColor Red
        exit
    }

    if ($PSCmdlet.ShouldProcess($AzureApplicationName, "Delete application")) {
        $deleteAadApplicationParams = @{
            Query              = "applications/$($getAadApplicationResponse.value[0].id)"
            AccessToken        = $AccessToken
            Method             = "DELETE"
            ExpectedStatusCode = 204
            GraphApiUrl        = $GraphApiUrl
        }
        $deleteAzureApplicationResponse = Invoke-GraphApiRequest @deleteAadApplicationParams

        if ($deleteAzureApplicationResponse.Successful -eq $false) {
            Write-Host "Unable to delete the Azure AD application. Please try again or delete it manually." -ForegroundColor Red
            exit
        }

        Write-Host "Deleted the Azure application: $AzureApplicationName successfully" -ForegroundColor Green
    }
}
