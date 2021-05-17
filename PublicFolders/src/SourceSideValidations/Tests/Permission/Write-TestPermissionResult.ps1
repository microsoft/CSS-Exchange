function Write-TestBadPermissionResult {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $TestResult
    )

    begin {
        $badPermissions = 0
    }

    process {
        if ($TestResult.TestName -eq "Permission" -and $TestResult.ResultType -eq "BadPermission") {
            $badPermissions++
        }
    }

    end {
        if ($badPermissions.Count -gt 0) {
            Write-Host
            Write-Host $badPermissions.Count "invalid permissions were found."
            Write-Host "The invalid permissions can be removed using the RemoveInvalidPermissions switch as follows:"
            Write-Host ".\SourceSideValidations.ps1 -Repair" -ForegroundColor Green
        }
    }
}