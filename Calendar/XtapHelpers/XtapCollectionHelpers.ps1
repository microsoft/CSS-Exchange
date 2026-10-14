# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Collects the sharing configuration from Exchange Online, or imports it from CLIXML files.
.DESCRIPTION
    Returns an object with OrganizationRelationship, AvailabilityAddressSpace, SharingPolicy and
    SharingPolicyAssignment properties. The raw data is also exported to CLIXML files in OutputFolder.
    The commands used are the ones listed in Part 1 of
    https://learn.microsoft.com/exchange/sharing/migrate-to-m365-xtap
#>
function Get-XtapSharingConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputFolder,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$FilePrefix,

        [Parameter(Mandatory = $false)]
        [string]$OrganizationRelationshipXml,

        [Parameter(Mandatory = $false)]
        [string]$AvailabilityAddressSpaceXml,

        [Parameter(Mandatory = $false)]
        [string]$SharingPolicyXml,

        [Parameter(Mandatory = $false)]
        [string]$SharingPolicyAssignmentXml,

        [Parameter(Mandatory = $false)]
        [switch]$ProcessUsers,

        [Parameter(Mandatory = $false)]
        [string]$Organization
    )

    $paths = @{
        OrganizationRelationship = Join-Path -Path $OutputFolder -ChildPath "${FilePrefix}OrganizationRelationships.xml"
        AvailabilityAddressSpace = Join-Path -Path $OutputFolder -ChildPath "${FilePrefix}AvailabilityAddressSpaces.xml"
        SharingPolicy            = Join-Path -Path $OutputFolder -ChildPath "${FilePrefix}SharingPolicies.xml"
        SharingPolicyAssignment  = Join-Path -Path $OutputFolder -ChildPath "${FilePrefix}SharingPolicyAssignments.xml"
    }

    $configuration = @{
        OrganizationRelationship = @()
        AvailabilityAddressSpace = @()
        SharingPolicy            = @()
        SharingPolicyAssignment  = $null
        Mode                     = "Offline"
        Paths                    = $paths
    }

    if ([string]::IsNullOrEmpty($OrganizationRelationshipXml)) {
        $configuration.Mode = "Live"
        foreach ($commandName in @("Get-OrganizationRelationship", "Get-AvailabilityAddressSpace", "Get-SharingPolicy")) {
            if ($null -eq (Get-Command -Name $commandName -ErrorAction SilentlyContinue)) {
                throw "$commandName wasn't found. Connect to Exchange Online PowerShell (Connect-ExchangeOnline) with an account assigned the Organization Management role, then run the script again."
            }
        }

        # Reserved for Microsoft internal use / delegated access, so only pass it to cmdlets that accept it.
        $organizationParameter = @{}
        if (-not [string]::IsNullOrWhiteSpace($Organization)) {
            foreach ($commandName in @("Get-OrganizationRelationship", "Get-AvailabilityAddressSpace", "Get-SharingPolicy")) {
                if (-not (Get-Command -Name $commandName).Parameters.ContainsKey("Organization")) {
                    throw "$commandName doesn't have an -Organization parameter in this session. Connect with access to the target organization instead."
                }
            }

            $organizationParameter = @{ Organization = $Organization }
            Write-Host "Collecting from organization $Organization."
        }

        Write-Host "Collecting Organization Relationships..."
        $configuration.OrganizationRelationship = @(Get-OrganizationRelationship @organizationParameter -ErrorAction Stop)
        Write-Host "Collecting Availability Address Spaces..."
        $configuration.AvailabilityAddressSpace = @(Get-AvailabilityAddressSpace @organizationParameter -ErrorAction Stop)
        Write-Host "Collecting Sharing Policies..."
        $configuration.SharingPolicy = @(Get-SharingPolicy @organizationParameter -ErrorAction Stop)

        $mailboxCommand = $null
        if (-not $ProcessUsers) {
            Write-Host "Skipping the Sharing Policy assignment query. Use -ProcessUsers to count the mailboxes assigned to each Sharing Policy."
        } else {
            # Customers have Get-EXOMailbox. Support sessions (and some others) only have Get-Mailbox.
            $mailboxCommandName = "Get-EXOMailbox"
            if ($null -eq (Get-Command -Name $mailboxCommandName -ErrorAction SilentlyContinue)) {
                $mailboxCommandName = "Get-Mailbox"
            }

            $mailboxCommand = Get-Command -Name $mailboxCommandName -ErrorAction SilentlyContinue
            if ($null -eq $mailboxCommand) {
                Write-Warning "Neither Get-EXOMailbox nor Get-Mailbox was found. Skipping the Sharing Policy assignment query."
            } elseif ($organizationParameter.Count -gt 0 -and -not $mailboxCommand.Parameters.ContainsKey("Organization")) {
                Write-Warning "$mailboxCommandName doesn't have an -Organization parameter in this session. Skipping the Sharing Policy assignment query so mailboxes from the wrong organization aren't counted."
                $mailboxCommand = $null
            }
        }

        if ($null -ne $mailboxCommand) {
            try {
                Write-Host "Counting mailboxes assigned to each Sharing Policy with $mailboxCommandName (this can take a while in large organizations)..."
                $mailboxParameter = @{ ResultSize = "Unlimited"; RecipientTypeDetails = @("UserMailbox", "SharedMailbox"); ErrorAction = "Stop" }
                if ($mailboxCommandName -eq "Get-EXOMailbox") {
                    $mailboxParameter["Properties"] = "SharingPolicy"
                }

                $configuration.SharingPolicyAssignment = @(& $mailboxCommandName @organizationParameter @mailboxParameter |
                        Group-Object -Property SharingPolicy | Select-Object -Property Name, Count)
            } catch {
                Write-Warning "Failed to collect the Sharing Policy assignments: $($_.Exception.Message)"
            }
        }
    } else {
        Write-Host "Importing collected data..."
        $configuration.OrganizationRelationship = @(Import-Clixml -LiteralPath $OrganizationRelationshipXml | ForEach-Object { $_ })
        $configuration.AvailabilityAddressSpace = @(Import-Clixml -LiteralPath $AvailabilityAddressSpaceXml | ForEach-Object { $_ })
        $configuration.SharingPolicy = @(Import-Clixml -LiteralPath $SharingPolicyXml | ForEach-Object { $_ })
        if (-not [string]::IsNullOrEmpty($SharingPolicyAssignmentXml)) {
            $configuration.SharingPolicyAssignment = @(Import-Clixml -LiteralPath $SharingPolicyAssignmentXml | ForEach-Object { $_ })
        }
    }

    Export-Clixml -InputObject $configuration.OrganizationRelationship -LiteralPath $paths.OrganizationRelationship
    Export-Clixml -InputObject $configuration.AvailabilityAddressSpace -LiteralPath $paths.AvailabilityAddressSpace
    Export-Clixml -InputObject $configuration.SharingPolicy -LiteralPath $paths.SharingPolicy
    if ($null -ne $configuration.SharingPolicyAssignment) {
        Export-Clixml -InputObject $configuration.SharingPolicyAssignment -LiteralPath $paths.SharingPolicyAssignment
    }

    [PSCustomObject]$configuration
}
