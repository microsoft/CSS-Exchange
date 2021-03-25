Function Test-KnownLdifErrors {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $SetupLogReviewer
    )
    begin {
        $diagnosticContext = New-Object 'System.Collections.Generic.List[string]'
        $displayContext = New-Object 'System.Collections.Generic.List[PSCustomObject]'
        $foundKnownIssue = $true
        $actionPlan = New-Object 'System.Collections.Generic.List[string]'
        $errorContext = New-Object 'System.Collections.Generic.List[string]'
        $writeErrorContext = New-Object 'System.Collections.Generic.List[string]'
        $writeWarning = [string]::Empty
    }
    process {

        $diagnosticContext.Add("KnownLdifErrors")
        $schemaImportProcessFailure = $SetupLogReviewer.SelectStringLastRunOfExchangeSetup("\[ERROR\] There was an error while running 'ldifde.exe' to import the schema file '(.*)'. The error code is: (\d+). More details can be found in the error file: '(.*)'")

        if ($null -ne $schemaImportProcessFailure) {
            $actionPlan.Add("Failed to import schema setting from file '$($schemaImportProcessFailure.Matches.Groups[1].Value)'")
            $actionPlan.Add("Review ldif.err file '$($schemaImportProcessFailure.Matches.Groups[3].Value)' to help determine which object in the file '$($schemaImportProcessFailure.Matches.Groups[1].Value)' was trying to be imported that was causing problems.")
            $actionPlan.Add("If you can't find the ldf file in the C:\Windows\Temp location, then find the file in the ISO.")
            return
        }
        $diagnosticContext.Add("KnownLdifErrors - no known issue")
        $foundKnownIssue = $false
        return
    }
    end {
        return [PSCustomObject]@{
            DiagnosticContext = $diagnosticContext
            DisplayContext    = $displayContext
            FoundKnownIssue   = $foundKnownIssue
            ActionPlan        = $actionPlan
            ErrorContext      = $errorContext
            WriteErrorContext = $writeErrorContext
            WriteWarning      = $writeWarning
        }
    }
}