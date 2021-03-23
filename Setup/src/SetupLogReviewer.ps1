# This script reviews the ExchangeSetup.log and determines if it is a known issue and reports an
# action to take to resolve the issue.
#
# Use the DelegateSetup switch if the log is from a Delegated Setup and you are running into a Prerequisite Check issue
#
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Parameter is used')]
[CmdletBinding(DefaultParameterSetName = "Main")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Main")]
    [System.IO.FileInfo]$SetupLog,
    [Parameter(ParameterSetName = "Main")]
    [switch]$DelegatedSetup,
    [Parameter(ParameterSetName = "PesterLoading")]
    [switch]$PesterLoad
)

. $PSScriptRoot\LogReviewer\Get-DelegatedInstallerHasProperRights.ps1
. $PSScriptRoot\LogReviewer\New-SetupLogReviewer.ps1
. $PSScriptRoot\LogReviewer\Test-KnownOrganizationPreparationErrors.ps1
. $PSScriptRoot\LogReviewer\Test-KnownIssuesByErrors.ps1
. $PSScriptRoot\LogReviewer\Test-KnownLdifErrors.ps1
. $PSScriptRoot\LogReviewer\Test-PrerequisiteCheck.ps1

Function Main {
    try {

        if ($PesterLoad) {
            return
        }

        if (-not ([IO.File]::Exists($SetupLog))) {
            Write-Error "Could not find file: $SetupLog"
            return
        }

        $setupLogReviewer = New-SetupLogReviewer -SetupLog $SetupLog -ErrorAction Stop
        $runDate = $setupLogReviewer.SetupRunDate
        $color = "Gray"

        if ($runDate -lt ([datetime]::Now.AddDays(-14))) { $color = "Yellow" }
        $setupLogReviewer.ReceiveOutput("Setup.exe Run Date: $runDate", $color)

        if ($null -ne $setupLogReviewer.LocalBuildNumber) {
            Write-Output "Current Exchange Build: $($setupLogReviewer.LocalBuildNumber)"

            if ($setupLogReviewer.LocalBuildNumber -eq $setupLogReviewer.SetupBuildNumber) {
                $setupLogReviewer.ReceiveOutput("Same build number detected..... if using powershell.exe to start setup. Make sure you do '.\setup.exe'", "Red")
            }
        }

        if ($DelegatedSetup) {
            Get-DelegatedInstallerHasProperRights -SetupLogReviewer $setupLogReviewer
            return
        }

        if (Test-PrerequisiteCheck -SetupLogReviewer $setupLogReviewer) {

            Write-Output "`r`nAdditional Context:"
            Write-Output ("User Logged On: $($setupLogReviewer.User)")

            $serverFQDN = $setupLogReviewer.GetEvaluatedSettingOrRule("ComputerNameDnsFullyQualified", "Setting", ".")

            if ($null -ne $serverFQDN) {
                $serverFQDN = $serverFQDN.Matches.Groups[1].Value
                Write-Output "Setup Running on: $serverFQDN"
                $setupDomain = $serverFQDN.Split('.')[1]
                Write-Output "Setup Running in Domain: $setupDomain"
            }

            $siteName = $setupLogReviewer.GetEvaluatedSettingOrRule("SiteName", "Setting", ".")

            if ($null -ne $siteName) {
                Write-Output "Setup Running in AD Site Name: $($siteName.Matches.Groups[1].Value)"
            }

            $schemaMaster = $setupLogReviewer.SelectStringLastRunOfExchangeSetup("Setup will attempt to use the Schema Master domain controller (.+)")

            if ($null -ne $schemaMaster) {
                Write-Output "----------------------------------"
                Write-Output "Schema Master: $($schemaMaster.Matches.Groups[1].Value)"
                $smDomain = $schemaMaster.Matches.Groups[1].Value.Split(".")[1]
                Write-Output "Schema Master in Domain: $smDomain"

                if ($smDomain -ne $setupDomain) {
                    $setupLogReviewer.ReceiveOutput("Unable to run setup in current domain.", "Red")
                }
            }
            return
        }

        if (Test-KnownLdifErrors -SetupLogReviewer $setupLogReviewer) {
            return
        }

        if (Test-KnownOrganizationPreparationErrors -SetupLogReviewer $setupLogReviewer) {
            return
        }

        if (Test-KnownIssuesByErrors -SetupLogReviewer $setupLogReviewer) {
            return
        }

        #Last Error Information
        $lastErrorInfo = $setupLogReviewer.FirstErrorWithContextToLine(-1,30,200)

        if ($null -ne $lastErrorInfo) {
            Write-Output "Failed to determine known cause, but here is your error context that we are seeing"
            $setupLogReviewer.WriteErrorContext($lastErrorInfo)
        }

        Write-Output "Looks like we weren't able to determine the cause of the issue with Setup. Please run SetupAssist.ps1 on the server." `
            "If that doesn't find the cause, please notify $($setupLogReviewer.FeedbackEmail) to help us improve the scripts."
    } catch {
        Write-Output "$($Error[0].Exception)"
        Write-Output "$($Error[0].ScriptStackTrace)"
        Write-Warning ("Ran into an issue with the script. If possible please email the Setup Log to 'ExToolsFeedback@microsoft.com', or at least notify them of the issue.")
    }
}

Main