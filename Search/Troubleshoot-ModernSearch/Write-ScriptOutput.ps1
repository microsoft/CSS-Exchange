. $PSScriptRoot\Write-LogInformation.ps1
Function Write-ScriptOutput {
    param(
        [Parameter(Position = 1, ValueFromPipeline = $true)]
        [object[]]$Object,
        [switch]$Diagnostic
    )

    process {

        if (($Diagnostic -and
                $VerbosePreference) -or
            -not ($Diagnostic)) {
            $Object | Write-Output
        } else {
            $Object | Write-Verbose
        }

        Write-LogInformation $Object -VerboseEnabled $false
    }
}
