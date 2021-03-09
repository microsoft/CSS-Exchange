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

$feedbackEmail = "ExToolsFeedback@microsoft.com"

# Get-DelegatedInstallerHasProperRights
#
# Identifies the issue described in https://support.microsoft.com/en-us/help/2961741
# by reading the setup log to see if this is why we failed.
#
# The article says this was fixed, but the fix was to add the Server Management
# group. The options are either add the delegated installer to that group, or
# remove them from whatever group is giving them too many rights (usually Domain Admins).

Function Receive-Output {
    param(
        [string]$ForegroundColor
    )
    process { Write-Host $_ -ForegroundColor $ForegroundColor }
}

Function Get-DelegatedInstallerHasProperRights {

    if ((Test-EvaluatedSettingOrRule -SettingName "EnterpriseAdmin") -eq "True") {
        Write-Output "User that ran setup has EnterpriseAdmin and does not need to be in Server Management."
        return
    }

    if ((Test-EvaluatedSettingOrRule -SettingName "ExOrgAdmin") -eq "True") {
        Write-Output "User that ran setup has ExOrgAdmin and does not need to be in Server Management."
        return
    }

    if ((Test-EvaluatedSettingOrRule -SettingName "ServerAlreadyExists") -eq "False") {
        Write-Output "ServerAlreadyExists check came back False, and the user that ran setup does not have ExOrgAdmin or EnterpriseAdmin." -
        return
    }

    if ($null -eq (Test-EvaluatedSettingOrRule -SettingName "HasServerDelegatedPermsBlocked")) {
        Write-Output "HasServerDelegatedPermsBlocked returned no rights. This means the user that ran setup" `
            "does not have extra rights, and thus does not need to be in Server Management."
        return
    }

    $serverManagementValue = Test-EvaluatedSettingOrRule -SettingName "ServerManagement"

    if ($serverManagementValue -eq "True") {
        Write-Output "User that ran setup has extra rights to the server object, but is also a member of Server Management, so it's fine."
        return
    } elseif ($serverManagementValue -eq "False") {
        Write-Output "User that ran setup has extra rights to the server object and is not in Server Management. This causes setup to fail." |
            Receive-Output -ForegroundColor Red
        return
    }
}

Function Get-EvaluatedSettingOrRule {
    param(
        [string]$SettingName,
        [string]$SettingOrRule = "Setting",
        [string]$ValueType = "\w"
    )
    return Select-String ("Evaluated \[{0}:{1}\].+\[Value:`"({2}+)`"\] \[ParentValue:" -f $SettingOrRule, $SettingName, $ValueType) $SetupLog | Select-Object -Last 1
}

Function Test-EvaluatedSettingOrRule {
    param(
        [string]$SettingName,
        [string]$SettingOrRule = "Setting"
    )
    $selectString = Get-EvaluatedSettingOrRule -SettingName $SettingName -SettingOrRule $SettingOrRule

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
        Write-Output ("Computer is pending reboot based off the Windows Component is the registry") |
            Receive-Output -ForegroundColor Red
        return $true
    }

    $adValidationError = Get-StringInLastRunOfExchangeSetup `
        -SelectStringPattern "\[ERROR\] Setup encountered a problem while validating the state of Active Directory: (.*) See the Exchange setup log for more information on this error."

    if ($adValidationError) {
        Write-Warning "Setup failed to validate AD environment level. This is the internal exception that occurred:"
        Write-Output($adValidationError.Matches.Groups[1].Value) |
            Receive-Output -ForegroundColor Yellow
        return $true
    }

    $schemaUpdateRequired = Get-StringInLastRunOfExchangeSetup `
        -SelectStringPattern "Schema Update Required Status : '(\w+)'."

    $orgConfigUpdateRequired = Get-StringInLastRunOfExchangeSetup `
        -SelectStringPattern "Organization Configuration Update Required Status : '(\w+)'."

    $domainConfigUpdateRequired = Get-StringInLastRunOfExchangeSetup `
        -SelectStringPattern "Domain Configuration Update Required Status : '(\w+)'."

    if ($schemaUpdateRequired.Matches.Groups[1].Value -eq "True" -and
        (Test-EvaluatedSettingOrRule -SettingName "SchemaAdmin") -eq "False") {
        Write-Output ("/PrepareSchema is required and user {0} isn't apart of the Schema Admins group." -f $currentLogOnUser) |
            Receive-Output -ForegroundColor Red
        return $true
    }

    if ($schemaUpdateRequired.Matches.Groups[1].Value -eq "True" -and
        (Test-EvaluatedSettingOrRule -SettingName "EnterpriseAdmin") -eq "False") {
        Write-Output ("/PrepareSchema is required and user {0} isn't apart of the Enterprise Admins group." -f $currentLogOnUser) |
            Receive-Output -ForegroundColor Red
        return $true
    }

    if ($orgConfigUpdateRequired.Matches.Groups[1].Value -eq "True" -and
        (Test-EvaluatedSettingOrRule -SettingName "EnterpriseAdmin") -eq "False") {
        Write-Output ("/PrepareAD is required and user {0} isn't apart of the Enterprise Admins group." -f $currentLogOnUser) |
            Receive-Output -ForegroundColor Red
        return $true
    }

    if ($domainConfigUpdateRequired.Matches.Groups[1].Value -eq "True" -and
        (Test-EvaluatedSettingOrRule -SettingName "EnterpriseAdmin") -eq "False") {
        Write-Output ("/PrepareDomain needs to be run in this domain, but we actually require Enterprise Admin group to properly run this command.") |
            Receive-Output -ForegroundColor Red
        return $true
    }

    if ((Test-EvaluatedSettingOrRule -SettingName "ExOrgAdmin") -eq "False") {
        $sid = Get-EvaluatedSettingOrRule -SettingName "SidExOrgAdmins" -ValueType "."
        if ($null -ne $sid) {
            Write-Output ("User {0} isn't apart of Organization Management group." -f $currentLogOnUser) |
                Receive-Output -ForegroundColor Red

            Write-Output ("Looking to be in this group SID: $($sid.Matches.Groups[1].Value)")
            return $true
        } else {
            Write-Output ("Didn't find the user to be in ExOrgAdmin, but didn't find the SID for the group either. Suspect /PrepareAD hasn't been run yet.") |
                Receive-Output -ForegroundColor Yellow
        }
    }

    return $false
}

Function Write-ErrorContext {
    param(
        [array]$WriteInfo
    )
    Write-Warning ("Found Error: `r`n")
    foreach ($line in $WriteInfo) {
        Write-Output $line |
            Receive-Output -ForegroundColor Yellow
    }
}

Function Write-ActionPlan {
    param(
        [string]$ActionPlan
    )
    Write-Output("`r`nDo the following action plan:`r`n`t{0}" -f $ActionPlan) |
        Receive-Output -ForegroundColor Gray
    Write-Output("`r`nIf this doesn't resolve your issues, please let us know at {0}" -f $feedbackEmail)
}

Function Write-LogicalError {
    $display = "Logical Error has occurred. Please notify {0}" -f $feedbackEmail
    Write-Error $display
}

Function Get-FirstErrorWithContextToErrorReference {
    param(
        [int]$Before = 0,
        [int]$After = 200,
        [int]$ErrorReferenceLine
    )
    $allErrors = Select-String "\[ERROR\]" $SetupLog -Context $Before, $After
    $errorContext = New-Object 'System.Collections.Generic.List[string]'

    foreach ($currentError in $allErrors) {
        if (Test-LastRunOfExchangeSetup -TestingMatchInfo $currentError) {

            if ($Before -ne 0) {
                $currentError.Context.PreContext |
                    ForEach-Object {
                        $errorContext.Add($_)
                    }
            }

            $errorContext.Add($currentError.Line)
            $linesWant = $ErrorReferenceLine - $currentError.LineNumber
            $i = 0
            while ($i -lt $linesWant) {
                $errorContext.Add($currentError.Context.PostContext[$i])
                $i++
            }
            return $errorContext
        }
    }
}

Function Test-KnownOrganizationPreparationErrors {

    $errorReference = Select-String "\[ERROR-REFERENCE\] Id=(.+) Component=" $SetupLog | Select-Object -Last 1

    if ($null -eq $errorReference -or
        !(Test-LastRunOfExchangeSetup -TestingMatchInfo $errorReference)) {
        return $false
    }

    $errorLine = Select-String "\[ERROR\] The well-known object entry (.+) on the otherWellKnownObjects attribute in the container object (.+) points to an invalid DN or a deleted object" $SetupLog | Select-Object -Last 1

    if ($null -ne $errorLine -and
        (Test-LastRunOfExchangeSetup -TestingMatchInfo $errorLine)) {

        Write-ErrorContext -WriteInfo $errorLine.Line
        [string]$ap = "Option 1: Restore the objects that were deleted."
        [string]$ap += "`r`n`tOption 2: Run the SetupAssist.ps1 script with '-OtherWellKnownObjectsContainer `"$($errorLine.Matches.Groups[2].Value)`"' to be able address deleted objects type"
        Write-ActionPlan $ap
        return $true
    }

    #_27a706ffe123425f9ee60cb02b930e81 initialize permissions of the domain.
    if ($errorReference.Matches.Groups[1].Value -eq "DomainGlobalConfig___27a706ffe123425f9ee60cb02b930e81") {
        $errorContext = Get-FirstErrorWithContextToErrorReference -Before 1 -ErrorReferenceLine $errorReference.LineNumber
        $permissionsError = $errorContext | Select-String "SecErr: DSID-03152857, problem 4003 \(INSUFF_ACCESS_RIGHTS\)"

        if ($null -ne $permissionsError) {
            $objectDN = $errorContext[0] | Select-String "Used domain controller (.+) to read object (.+)."

            if ($null -ne $objectDN) {
                Write-ErrorContext -WriteInfo ($errorContext | Select-Object -First 10)
                [string]$ap = "We failed to have the correct permissions to write ACE to '$($objectDN.Matches.Groups[2].Value)' as the current user $Script:currentLogOnUser"
                [string]$ap += "`r`n`t- Make sure there are no denies for this user on the object"
                [string]$ap += "`r`n`t- By default Enterprise Admins and BUILTIN\Administrators give you the rights to do this action (dsacls 'write permissions')"
                [string]$ap += "`r`n`t- If unable to determine the cause, you can apply FULL CONTROL to '$($objectDN.Matches.Groups[2].Value)' for the user $Script:currentLogOnUser"
                Write-ActionPlan $ap
                return $true
            }
        }
    }
}

Function Test-KnownErrorReferenceSetupIssues {

    $errorReference = Select-String "\[ERROR-REFERENCE\] Id=(.+) Component=" $SetupLog | Select-Object -Last 1

    if ($null -eq $errorReference -or
        !(Test-LastRunOfExchangeSetup -TestingMatchInfo $errorReference)) {
        return $false
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
        $ap = "- Change the {0} object to {1}" -f $invalidWKObjectTargetException.Matches.Groups[3].Value,
        $invalidWKObjectTargetException.Matches.Groups[4].Value
        $ap += "`r`n`t- Another problem can be that the group is set correctly, but is mail enabled and shouldn't be."
        Write-ActionPlan ($ap)

        return $true
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
            return $true
        }
    }

    $exceptionADOperationFailedAlreadyExist = $errorContext | Select-String `
        -Pattern "Active Directory operation failed on (.+). The object '(.+)' already exists." `
    | Select-Object -First 1

    if ($null -ne $exceptionADOperationFailedAlreadyExist) {
        Write-ErrorContext -WriteInfo $exceptionADOperationFailedAlreadyExist.Line
        Write-ActionPlan("Validate permissions are inherited to object `"{0}`" and that there aren't any denies that shouldn't be there" -f $exceptionADOperationFailedAlreadyExist.Matches.Groups[2])
        return $true
    }

    return $false
}

Function Test-OtherKnownIssues {

    if ((Test-EvaluatedSettingOrRule -SettingName "DidOnPremisesSettingCreatedAnException" -SettingOrRule "Rule") -eq "True") {
        $isHybridObjectFoundOnPremises = Select-String "Evaluated \[Setting:IsHybridObjectFoundOnPremises\]" $SetupLog -Context 20, 20 | Select-Object -Last 1

        if ($null -eq $isHybridObjectFoundOnPremises -or
            !(Test-LastRunOfExchangeSetup -TestingMatchInfo $isHybridObjectFoundOnPremises)) {
            Write-LogicalError
            return $true
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
            return $true
        }

        Write-ErrorContext -WriteInfo $errorContext
        Write-ActionPlan("One of the Organization Relationship objects has a null value to the ApplicationURI attribute. `r`n`tPlease add `"{0}`" to it" -f $targetApplicationUri.Matches.Groups[1].Value)
        return $true
    }

    return $false
}

Function Test-KnownLdifErrors {
    $schemaImportProcessFailure = Select-String "\[ERROR\] There was an error while running 'ldifde.exe' to import the schema file '(.*)'. The error code is: (\d+). More details can be found in the error file: '(.*)'" $SetupLog | Select-Object -Last 1

    if ($null -ne $schemaImportProcessFailure) {
        Write-ActionPlan("Failed to import schema setting from file '{0}'`r`n`tReview ldif.err file '{1}' to help determine which object in the file '{0}' was trying to be imported that was causing problems.`r`n`tIf you can't find the ldf file in the C:\Windows\Temp location, then find the file in the ISO." -f $schemaImportProcessFailure.Matches.Groups[1].Value,
            $schemaImportProcessFailure.Matches.Groups[3].Value)
        return $true
    }

    return $false
}

Function Main {
    try {

        if ($PesterLoad) {
            return
        }

        if (-not ([IO.File]::Exists($SetupLog))) {
            Write-Error "Could not find file: $SetupLog"
            return
        }

        $Script:validSetupLog = Select-String "Starting Microsoft Exchange Server \d\d\d\d Setup" $SetupLog | Select-Object -Last 1
        if ($null -eq $validSetupLog) {
            Write-Error "Failed to provide valid Exchange Setup Log"
            return
        }

        $Script:currentLogOnUser = Get-EvaluatedSettingOrRule -SettingName "CurrentLogOn" -ValueType "."

        if ($null -ne $Script:currentLogOnUser) {
            $Script:currentLogOnUser = $Script:currentLogOnUser.Matches.Groups[1].Value
        }

        $Script:SetupBuildNumber = Select-String "Setup version: (.+)\." $SetupLog | Select-Object -Last 1
        $runDate = [DateTime]::Parse(
            $SetupBuildNumber.Line.Substring(1,
                $SetupBuildNumber.Line.IndexOf("]") - 1)
        )

        $color = "Gray"
        if ($runDate -lt ([datetime]::Now.AddDays(-14))) {
            $color = "Yellow"
        }

        Write-Output("Setup.exe Run Date: $runDate") |
            Receive-Output -ForegroundColor $color
        $Script:SetupBuildNumber = $Script:SetupBuildNumber.Matches.Groups[1].Value
        $localInstall = Get-StringInLastRunOfExchangeSetup -SelectStringPattern "The locally installed version is (.+)\."

        if ($null -ne $localInstall) {
            $exBuild = $localInstall.Matches.Groups[1].Value
            Write-Output "Current Exchange Build: $exBuild"

            if ($exBuild -eq $SetupBuildNumber) {
                Write-Output "Same build number detected..... if using powershell.exe to start setup. Make sure you do '.\setup.exe'" |
                    Receive-Output -ForegroundColor Red
            }
        }

        if ($DelegatedSetup) {
            Get-DelegatedInstallerHasProperRights
            return
        }

        if (Test-PrerequisiteCheck) {

            Write-Output "`r`nAdditional Context:"
            Write-Output ("User Logged On: {0}" -f $Script:currentLogOnUser)

            $serverFQDN = Get-EvaluatedSettingOrRule -SettingName "ComputerNameDnsFullyQualified" -ValueType "."

            if ($null -ne $serverFQDN) {
                $serverFQDN = $serverFQDN.Matches.Groups[1].Value
                Write-Output "Setup Running on: $serverFQDN"
                $setupDomain = $serverFQDN.Split('.')[1]
                Write-Output "Setup Running in Domain: $setupDomain"
            }

            $siteName = Get-EvaluatedSettingOrRule -SettingName "SiteName" -ValueType "."

            if ($null -ne $siteName) {
                Write-Output "Setup Running in AD Site Name: $($siteName.Matches.Groups[1].Value)"
            }

            $schemaMaster = Get-StringInLastRunOfExchangeSetup -SelectStringPattern "Setup will attempt to use the Schema Master domain controller (.+)"

            if ($null -ne $schemaMaster) {
                Write-Output "----------------------------------"
                Write-Output "Schema Master: $($schemaMaster.Matches.Groups[1].Value)"
                $smDomain = $schemaMaster.Matches.Groups[1].Value.Split(".")[1]
                Write-Output "Schema Master in Domain: $smDomain"

                if ($smDomain -ne $setupDomain) {
                    Write-Output "Unable to run setup in current domain." |
                        Receive-Output -ForegroundColor "Red"
                }
            }

            return
        }

        if (Test-KnownLdifErrors) {
            return
        }

        if (Test-KnownOrganizationPreparationErrors) {
            return
        }

        if (Test-KnownErrorReferenceSetupIssues) {
            return
        }

        if (Test-OtherKnownIssues) {
            return
        }

        Write-Output "Looks like we weren't able to determine the cause of the issue with Setup. Please run SetupAssist.ps1 on the server." `
            "If that doesn't find the cause, please notify $feedbackEmail to help us improve the scripts."
    } catch {
        Write-Output "$($Error[0].Exception)"
        Write-Output "$($Error[0].ScriptStackTrace)"
        Write-Warning ("Ran into an issue with the script. If possible please email the Setup Log to {0}, or at least notify them of the issue." -f $feedbackEmail)
    }
}

Main