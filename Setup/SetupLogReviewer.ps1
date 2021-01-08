# This script reviews the ExchangeSetup.log and determines if it is a known issue and reports an
# action to take to resolve the issue.
#
# Use the DelegateSetup switch if the log is from a Delegated Setup and you are running into a Prerequisite Check issue
#
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Parameter is used')]
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [System.IO.FileInfo]$SetupLog,
    [switch]$DelegatedSetup
)

$feedbackEmail = "ExToolsFeedback@microsoft.com"

# Get-DelegatedInstallerHasProperRights
#
# Identifies the issue described in https://support.microsoft.com/en-us/help/2961741
# by reading the setup log to see if this is why we failed.
#
# The article says this was fixed, but the fix was to add the Server Management
# group. The options are either add the delegated installer to that group, or
# remove them from whatever group is giving them too many rights (usually Domain Admins).

Function Get-DelegatedInstallerHasProperRights {

    if ((Test-EvaluatedSettingOrRule -SettingName "EnterpriseAdmin") -eq "True") {
        Write-Host "User that ran setup has EnterpriseAdmin and does not need to be in Server Management."
        return
    }

    if ((Test-EvaluatedSettingOrRule -SettingName "ExOrgAdmin") -eq "True") {
        Write-Host "User that ran setup has ExOrgAdmin and does not need to be in Server Management."
        return
    }

    if ((Test-EvaluatedSettingOrRule -SettingName "ServerAlreadyExists") -eq "False") {
        Write-Error "ServerAlreadyExists check came back False, and the user that ran setup does not have ExOrgAdmin or EnterpriseAdmin."
        return
    }

    if ($null -eq (Test-EvaluatedSettingOrRule -SettingName "HasServerDelegatedPermsBlocked")) {
        Write-Host "HasServerDelegatedPermsBlocked returned no rights. This means the user that ran setup" `
            "does not have extra rights, and thus does not need to be in Server Management."
        return
    }

    $serverManagementValue = Test-EvaluatedSettingOrRule -SettingName "ServerManagement"

    if ($serverManagementValue -eq "True") {
        Write-Host "User that ran setup has extra rights to the server object, but is also a member of Server Management, so it's fine."
        return
    } elseif ($serverManagementValue -eq "False") {
        Write-Error "User that ran setup has extra rights to the server object and is not in Server Management. This causes setup to fail."
        return
    }
}

Function Test-EvaluatedSettingOrRule {
    param(
        [string]$SettingName,
        [string]$SettingOrRule = "Setting"
    )
    $selectString = Select-String ("Evaluated \[{0}:{1}\].+\[Value:`"(\w+)`"`]" -f $SettingOrRule, $SettingName) $SetupLog | Select-Object -Last 1

    if ($null -ne $selectString -and
        (Test-LastRunOfExchangeSetup -TestingMatchInfo $selectString) -and
        $null -ne $selectString.Matches) {
        $selectStringValue = $selectString.Matches.Groups[1].Value

        if ($selectStringValue -ne "True" -and
            $selectStringValue -ne "False") {
            Write-Error ("{0} check has unexpected value: {1}" -f $SettingName, $selectStringValue)
            exit
        }
        return $selectStringValue
    }
    #Only need to handle this if the Evaluated setting might not occur all the time.
    return $null
}

Function Test-LastRunOfExchangeSetup {
    param(
        [object]$TestingMatchInfo
    )
    return $TestingMatchInfo.LineNumber -gt $Script:validSetupLog.LineNumber
}

Function Get-StringInLastRunOfExchangeSetup {
    param(
        [string]$SelectStringPattern
    )
    $selectStringResults = Select-String $SelectStringPattern $SetupLog | Select-Object -Last 1

    if ($null -ne $selectStringResults -and
        (Test-LastRunOfExchangeSetup -TestingMatchInfo $selectStringResults)) {
        return $selectStringResults
    }
    return $null
}

Function Test-PrerequisiteCheck {

    if ((Test-EvaluatedSettingOrRule -SettingName "PendingRebootWindowsComponents" -SettingOrRule "Rule") -eq "True") {
        Write-Error ("Computer is pending reboot based off the Windows Component is the registry")
        return 1
    }

    $adValidationError = Get-StringInLastRunOfExchangeSetup `
        -SelectStringPattern "\[ERROR\] Setup encountered a problem while validating the state of Active Directory: (.*) See the Exchange setup log for more information on this error."

    if ($adValidationError) {
        Write-Warning "Setup failed to validate AD environment level. This is the internal exception that occurred:"
        Write-Host($adValidationError.Matches.Groups[1].Value) -ForegroundColor Yellow
        return 1
    }

    $schemaUpdateRequired = Get-StringInLastRunOfExchangeSetup `
        -SelectStringPattern "Schema Update Required Status : '(\w+)'."

    $orgConfigUpdateRequired = Get-StringInLastRunOfExchangeSetup `
        -SelectStringPattern "Organization Configuration Update Required Status : '(\w+)'."

    $domainConfigUpdateRequired = Get-StringInLastRunOfExchangeSetup `
        -SelectStringPattern "Domain Configuration Update Required Status : '(\w+)'."

    if ($schemaUpdateRequired.Matches.Groups[1].Value -eq "True" -and
        (Test-EvaluatedSettingOrRule -SettingName "SchemaAdmin") -eq "False") {
        Write-Error ("/PrepareSchema is required and user {0} isn't apart of the Schema Admins group." -f $currentLogOnUser)
        return 1
    }

    if ($schemaUpdateRequired.Matches.Groups[1].Value -eq "True" -and
        (Test-EvaluatedSettingOrRule -SettingName "EnterpriseAdmin") -eq "False") {
        Write-Error ("/PrepareSchema is required and user {0} isn't apart of the Enterprise Admins group." -f $currentLogOnUser)
        return 1
    }

    if ($orgConfigUpdateRequired.Matches.Groups[1].Value -eq "True" -and
        (Test-EvaluatedSettingOrRule -SettingName "EnterpriseAdmin") -eq "False") {
        Write-Error ("/PrepareAD is required and user {0} isn't apart of the Enterprise Admins group." -f $currentLogOnUser)
        return 1
    }

    if ($domainConfigUpdateRequired.Matches.Groups[1].Value -eq "True" -and
        (Test-EvaluatedSettingOrRule -SettingName "EnterpriseAdmin") -eq "False") {
        Write-Error ("/PrepareDomain needs to be run in this domain, but we actually require Enterprise Admin group to properly run this command.")
        return 1
    }

    if ((Test-EvaluatedSettingOrRule -SettingName "ExOrgAdmin") -eq "False") {
        Write-Error ("User {0} isn't apart of Organization Management group." -f $currentLogOnUser)
        return 1
    }
}

Function Write-ErrorContext {
    param(
        [array]$WriteInfo
    )
    Write-Warning ("Found Error: `r`n")
    foreach ($line in $WriteInfo) {
        Write-Host $line -ForegroundColor Yellow
    }
}

Function Write-ActionPlan {
    param(
        [string]$ActionPlan
    )
    Write-Host("`r`nDo the following action plan:`r`n`t{0}" -f $ActionPlan)
    Write-Host("`r`nIf this doesn't resolve your issues, please let us know at {0}" -f $feedbackEmail)
}

Function Write-LogicalError {
    $display = "Logical Error has occurred. Please notify {0}" -f $feedbackEmail
    Write-Error $display
}

Function Test-KnownErrorReferenceSetupIssues {

    $errorReference = Select-String "\[ERROR-REFERENCE\] Id=(.+) Component=" $SetupLog | Select-Object -Last 1

    if ($null -eq $errorReference -or
        !(Test-LastRunOfExchangeSetup -TestingMatchInfo $errorReference)) {
        return
    }

    $allErrors = Select-String "\[ERROR\]" $SetupLog -Context 0, 200
    $errorContext = @()

    foreach ($currentError in $allErrors) {
        if (Test-LastRunOfExchangeSetup -TestingMatchInfo $currentError) {
            #from known cases, this should be rather small
            $linesWant = $errorReference.LineNumber - $currentError.LineNumber
            $i = 0
            while ($i -lt $linesWant) {
                $errorContext += $currentError.Context.PostContext[$i++]
            }
            break
        }
    }

    $invalidWKObjectTargetException = $errorContext | Select-String `
        -Pattern "The well-known object entry with the GUID `"(.+)`", which is on the `"(.+)`" container object's otherWellKnownObjects attribute, refers to a group `"(.+)`" of the wrong group type. Either delete the well-known object entry, or promote the target object to `"(.+)`"." `
    | Select-Object -Last 1

    if ($null -ne $invalidWKObjectTargetException) {
        Write-ErrorContext -WriteInfo $invalidWKObjectTargetException.Line
        Write-ActionPlan ("Change the {0} object to {1}" -f $invalidWKObjectTargetException.Matches.Groups[3].Value,
            $invalidWKObjectTargetException.Matches.Groups[4].Value)

        return 1
    }

    $msExchangeSecurityGroupsContainerDeleted = $errorContext | Select-String `
        -Pattern "System.NullReferenceException: Object reference not set to an instance of an object.", `
        "Microsoft.Exchange.Management.Tasks.InitializeExchangeUniversalGroups.CreateOrMoveEWPGroup\(ADGroup ewp, ADOrganizationalUnit usgContainer\)"

    if ($null -ne $msExchangeSecurityGroupsContainerDeleted) {
        if ($msExchangeSecurityGroupsContainerDeleted[0].Pattern -ne $msExchangeSecurityGroupsContainerDeleted[1].Pattern -and
            $msExchangeSecurityGroupsContainerDeleted[0].LineNumber -eq ($msExchangeSecurityGroupsContainerDeleted[1].LineNumber - 1)) {
            Write-ErrorContext -WriteInfo @($msExchangeSecurityGroupsContainerDeleted[0].Line,
                $msExchangeSecurityGroupsContainerDeleted[1].Line)
            Write-ActionPlan("'OU=Microsoft Exchange Security Groups' was deleted from the root of the domain. We need to have it created again at the root of the domain to continue.")
            return 1
        }
    }

    $exceptionADOperationFailedAlreadyExist = $errorContext | Select-String `
        -Pattern "Active Directory operation failed on (.+). The object '(.+)' already exists." `
    | Select-Object -First 1

    if ($null -ne $exceptionADOperationFailedAlreadyExist) {
        Write-ErrorContext -WriteInfo $exceptionADOperationFailedAlreadyExist.Line
        Write-ActionPlan("Validate permissions are inherited to object `"{0}`" and that there aren't any denies that shouldn't be there" -f $exceptionADOperationFailedAlreadyExist.Matches.Groups[2])
        return 1
    }
}

Function Test-OtherKnownIssues {

    if ((Test-EvaluatedSettingOrRule -SettingName "DidOnPremisesSettingCreatedAnException" -SettingOrRule "Rule") -eq "True") {
        $isHybridObjectFoundOnPremises = Select-String "Evaluated \[Setting:IsHybridObjectFoundOnPremises\]" $SetupLog -Context 20, 20 | Select-Object -Last 1

        if ($null -eq $isHybridObjectFoundOnPremises -or
            !(Test-LastRunOfExchangeSetup -TestingMatchInfo $isHybridObjectFoundOnPremises)) {
            Write-LogicalError
            return 1
        }

        $errorContext = @()

        foreach ($line in $isHybridObjectFoundOnPremises.Context.PreContext) {
            $errorContext += $line
        }

        foreach ($line in $isHybridObjectFoundOnPremises.Context.PostContext) {
            $errorContext += $line
        }

        $targetApplicationUri = $errorContext | Select-String `
            "Searching for (.+) as the TargetApplicationUri"

        if ($null -eq $targetApplicationUri -or
            $targetApplicationUri.Count -gt 1) {
            Write-LogicalError
            return 1
        }

        Write-ErrorContext -WriteInfo $errorContext
        Write-ActionPlan("One of the Organization Relationship objects has a null value to the ApplicationURI attribute. `r`n`tPlease add `"{0}`" to it" -f $targetApplicationUri.Matches.Groups[1].Value)
        return 1
    }
}

Function Main {
    try {
        if (-not ([IO.File]::Exists($SetupLog))) {
            Write-Error "Could not find file: $SetupLog"
            return
        }

        $Script:validSetupLog = Select-String "Starting Microsoft Exchange Server \d\d\d\d Setup" $SetupLog | Select-Object -Last 1
        if ($null -eq $validSetupLog) {
            Write-Error "Failed to provide valid Exchange Setup Log"
            return
        }

        $Script:currentLogOnUser = Test-EvaluatedSettingOrRule -SettingName "CurrentLogOn"

        if ($DelegatedSetup) {
            Get-DelegatedInstallerHasProperRights
            return
        }

        if (Test-PrerequisiteCheck) {
            return
        }

        if (Test-KnownErrorReferenceSetupIssues) {
            return
        }

        if (Test-OtherKnownIssues) {
            return
        }

        Write-Host "Looks like we weren't able to determine the cause of the issue with Setup. Please run SetupAssist.ps1 on the server." `
            "If that doesn't find the cause, please notify {0} to help us improve the scripts." -f $feedbackEmail
    } catch {
        Write-Warning "Ran into an issue with the script. If possible please email the Setup Log to {0}, or at least notify them of the issue." -f $feedbackEmail
    }
}

Main