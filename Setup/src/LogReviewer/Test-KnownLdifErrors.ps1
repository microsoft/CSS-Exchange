Function Test-KnownLdifErrors {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $SetupLogReviewer
    )
    process {

        $schemaImportProcessFailure = $SetupLogReviewer.SelectStringLastRunOfExchangeSetup("\[ERROR\] There was an error while running 'ldifde.exe' to import the schema file '(.*)'. The error code is: (\d+). More details can be found in the error file: '(.*)'")

        if ($null -ne $schemaImportProcessFailure) {
            $SetupLogReviewer.WriteActionPlan(("Failed to import schema setting from file '{0}'`r`n`tReview ldif.err file '{1}' to help determine which object in the file '{0}' was trying to be imported that was causing problems.`r`n`tIf you can't find the ldf file in the C:\Windows\Temp location, then find the file in the ISO." -f $schemaImportProcessFailure.Matches.Groups[1].Value,
                    $schemaImportProcessFailure.Matches.Groups[3].Value))
            return $true
        }
        return $false
    }
}