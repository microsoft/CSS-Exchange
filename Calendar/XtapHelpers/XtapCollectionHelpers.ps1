# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Collects the sharing configuration from Exchange Online, or imports a JSON bundle.
.DESCRIPTION
    Returns an object with OrganizationRelationship, AvailabilityAddressSpace, SharingPolicy and
    SharingPolicyAssignment properties. Exchange-specific values are normalized for JSON replay.
    The commands used are the ones listed in Part 1 of
    https://learn.microsoft.com/exchange/sharing/migrate-to-m365-xtap
#>
function Get-XtapSharingConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ImportData,

        [Parameter(Mandatory = $false)]
        [switch]$ProcessUsers,

        [Parameter(Mandatory = $false)]
        [string]$Organization
    )

    $configuration = @{
        OrganizationRelationship = @()
        AvailabilityAddressSpace = @()
        SharingPolicy            = @()
        SharingPolicyAssignment  = $null
        Mode                     = "Offline"
        Metadata                 = $null
        TenantResolution         = @()
    }

    if ([string]::IsNullOrEmpty($ImportData)) {
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
        $configuration.OrganizationRelationship = @(Get-OrganizationRelationship @organizationParameter -ErrorAction Stop |
                ConvertTo-XtapConfigurationItem)
        Write-Host "Collecting Availability Address Spaces..."
        $configuration.AvailabilityAddressSpace = @(Get-AvailabilityAddressSpace @organizationParameter -ErrorAction Stop |
                ConvertTo-XtapConfigurationItem)
        Write-Host "Collecting Sharing Policies..."
        $configuration.SharingPolicy = @(Get-SharingPolicy @organizationParameter -ErrorAction Stop |
                ConvertTo-XtapConfigurationItem)

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
        Write-Host "Importing collected JSON data..."
        $data = Get-Content -LiteralPath $ImportData -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $data -or $data.SchemaVersion -ne 1 -or
            $data.Metadata.ScriptName -ne "CrossTenantAccessPolicyCalendarValidation") {
            throw "ImportData must be a version 1 CrossTenantAccessPolicyCalendarValidation JSON bundle."
        }
        $runNameProperty = $data.Metadata.PSObject.Properties["RunName"]
        $savedRunName = if ($null -ne $runNameProperty) { $runNameProperty.Value } else { $data.Metadata.CustomerName }
        if ($data.Metadata.TenantResolutionSkipped -isnot [bool] -or
            $data.Metadata.EntraLoginHost -isnot [string] -or
            $data.Metadata.EntraLoginHost -notmatch '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$' -or
            [uri]::CheckHostName($data.Metadata.EntraLoginHost) -ne [UriHostNameType]::Dns -or
            ($null -ne $savedRunName -and $savedRunName -isnot [string]) -or
            ($null -ne $data.Metadata.Organization -and $data.Metadata.Organization -isnot [string])) {
            throw "ImportData contains invalid collection metadata."
        }
        $data.Metadata | Add-Member -NotePropertyName RunName -NotePropertyValue $savedRunName -Force

        $requiredProperties = @{
            OrganizationRelationship = @("Name", "DomainNames", "Enabled", "FreeBusyAccessEnabled", "MailTipsAccessEnabled")
            AvailabilityAddressSpace = @("ForestName", "AccessMethod")
            SharingPolicy            = @("Name", "Enabled", "Default", "Domains")
            SharingPolicyAssignment  = @("Name", "Count")
        }
        foreach ($name in @("OrganizationRelationship", "AvailabilityAddressSpace", "SharingPolicy", "SharingPolicyAssignment")) {
            $property = $data.Configuration.PSObject.Properties[$name]
            if ($null -eq $property -or
                ($null -ne $property.Value -and $property.Value -isnot [array]) -or
                ($null -eq $property.Value -and $name -ne "SharingPolicyAssignment")) {
                throw "ImportData has an invalid or missing Configuration.$name collection."
            }
            foreach ($item in $property.Value) {
                if ($item -isnot [PSCustomObject]) {
                    throw "ImportData Configuration.$name must contain configuration objects."
                }
                foreach ($requiredProperty in $requiredProperties[$name]) {
                    if ($null -eq $item.PSObject.Properties[$requiredProperty]) {
                        throw "ImportData Configuration.$name has an item missing $requiredProperty."
                    }
                }
                foreach ($booleanProperty in @("Enabled", "Default", "FreeBusyAccessEnabled", "MailTipsAccessEnabled")) {
                    if ($null -ne $item.PSObject.Properties[$booleanProperty] -and $item.$booleanProperty -isnot [bool]) {
                        throw "ImportData Configuration.$name contains an invalid $booleanProperty value."
                    }
                }
                foreach ($arrayProperty in @("DomainNames", "Domains")) {
                    if ($null -ne $item.PSObject.Properties[$arrayProperty] -and
                        ($item.$arrayProperty -isnot [array] -or @($item.$arrayProperty | Where-Object { $_ -isnot [string] }).Count -gt 0)) {
                        throw "ImportData Configuration.$name contains an invalid $arrayProperty array."
                    }
                }
                if ($name -eq "SharingPolicyAssignment" -and
                    ($item.Count -isnot [long] -and $item.Count -isnot [int] -or $item.Count -lt 0)) {
                    throw "ImportData contains an invalid Sharing Policy mailbox count."
                }
            }
            $configuration[$name] = $property.Value
        }
        if ($data.TenantResolution -isnot [array]) {
            throw "ImportData must contain a TenantResolution array."
        }
        foreach ($entry in $data.TenantResolution) {
            if ($entry -isnot [PSCustomObject] -or $entry.Domain -isnot [string] -or
                $entry.Domain -notmatch '^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$' -or
                $null -eq $entry.PSObject.Properties["TenantId"] -or
                ($null -ne $entry.TenantId -and ($entry.TenantId -isnot [string] -or $entry.TenantId -notmatch $Script:XtapGuidPattern))) {
                throw "ImportData contains an invalid tenant resolution entry."
            }
            $resolutionError = $entry.PSObject.Properties["Error"]
            if ($null -ne $resolutionError -and $null -ne $resolutionError.Value -and
                $resolutionError.Value -isnot [string]) {
                throw "ImportData contains an invalid tenant resolution error."
            }
        }
        $configuration.Metadata = $data.Metadata
        $configuration.TenantResolution = $data.TenantResolution
    }

    [PSCustomObject]$configuration
}

function ConvertTo-XtapConfigurationItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$InputObject
    )

    process {
        $item = [ordered]@{}
        foreach ($property in $InputObject.PSObject.Properties) {
            $value = $property.Value
            # Exchange domain, enum, URI, and directory identity objects must retain their display values on replay.
            if ($null -eq $value -or $value -is [string] -or $value -is [bool] -or
                $value -is [byte] -or $value -is [int16] -or $value -is [int32] -or
                $value -is [int64] -or $value -is [decimal] -or $value -is [double]) {
                $item[$property.Name] = $value
            } elseif ($value -is [System.Collections.IEnumerable] -and $value -isnot [System.Collections.IDictionary]) {
                $item[$property.Name] = @(ConvertTo-CalendarDiagnosticPlainStringList -Value @($value))
            } else {
                $item[$property.Name] = ConvertTo-CalendarDiagnosticPlainString -Value $value
            }
        }
        [PSCustomObject]$item
    }
}
