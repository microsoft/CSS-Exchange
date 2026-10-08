# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# email providers
#cspell:words Gmail, GoogleMail, AmazonSES, Proofpoint, Pphosted, Mimecast

# DKIM Providers
#cspell:words Mailchimp, smtpapi, Mailgun, mailo, scph, Zendesk, Salesforce, Klaviyo, AWeber, GetResponse, ConvertKit, Infusionsoft, Pardot, Marketo, Eloqua, Sendlane, Moosend, Omnisend, EmailOctopus, Sendinblue, Elasticemail, Pepipost, Socketlabs, Mailjet, Dynadot, Zoho, Protonmail, Fastmail, RackSpace, Bluehost, Namecheap, Plesk

# protocol words
#cspell:words softfail, softpass, permerror, temperror, compauth, adkim, aspf, NSPM, BIMP, DIMP, FTBP, HPHSH, HPHISH, HSPM, INTOS, MALW, OSPM, PHSH, SPOOF, UIMP, dmarc, domainkey, mxvault

#html tags
#cspell:words onclick, thead, tbody, colgroup, mouseleave, mouseenter, ctry, darr, minmax, rgba, nowrap, uarr, onmouseover, onmouseout, linecap, dashoffset, dasharray

#Fonts
#cspell:words Lucida, Verdana, Tahoma, Segoe

<#
.SYNOPSIS
    Comprehensive email authentication analysis tool for SPF, DKIM, and DMARC records with documentation integration and enhanced security analysis.

    This script has been thoroughly tested across various environments and scenarios, and all tests have passed successfully. However, by using this script, you acknowledge and agree that:
    1. You are responsible for how you use the script and any outcomes resulting from its execution.
    2. The entire risk arising out of the use or performance of the script remains with you.
    3. The author and contributors are not liable for any damages, including data loss, business interruption, or other losses, even if warned of the risks.

.DESCRIPTION
    The Email Authentication Checker analyzes email authentication configurations for domains, providing detailed validation of SPF, DKIM, and DMARC records.
    The tool performs comprehensive security checks including DNS lookup validation, TTL analysis, macro security assessment, syntax validation, SPF enforcement rule analysis, and DMARC failure options evaluation.
    It generates professional HTML reports with interactive visualizations and provides actionable recommendations with direct links to Microsoft's
    official documentation if MX record points to Exchange Online or industry standard documentation if MX record points to another provider. Enhanced with authoritative DNS server queries for accurate TTL validation and record retrieval.

    This script operates in parameter-only mode and supports 4 analysis modes:
    1. Single Domain Analysis - Use -Domain parameter
    2. Multiple Domain Analysis - Use -DomainList parameter (comma-separated)
    3. Load Domains from File - Use -FilePath parameter (one domain per line)
    4. Email Header Analysis - Use -HeaderFilePath parameter

    Features 19 comprehensive security checks:
    - SPF (9 checks): Record presence, syntax, single record compliance, DNS lookups, length validation, TTL analysis, SPF enforcement rule, macro security, sub-record TTL (A/MX/TXT)
    - DMARC (5 checks): Record presence, policy assessment, reporting configuration, alignment modes, TTL validation
    - DKIM (5 checks): Selector discovery, syntax validation, key status analysis, strength assessment, TTL validation

.PARAMETER Domain
    Single domain to analyze (e.g., example.com). Use this parameter for single domain analysis.

.PARAMETER DomainList
    Multiple domains separated by commas (e.g., "example.com,contoso.com"). Use this parameter for multiple domain analysis.

.PARAMETER FilePath
    Path to a text file containing domains (one per line). Use this parameter for file-based analysis.

.PARAMETER HeaderFilePath
    Path to a text file containing email headers. Use this parameter for email header analysis.

.PARAMETER OutputPath
    Directory path where the HTML report will be saved. Defaults to current directory if not specified.

.PARAMETER AutoOpen
    Automatically open the HTML report in the default browser when analysis is complete.

.EXAMPLE
    .\EmailAuthChecker.ps1 -Domain "microsoft.com"
    Analyze a single domain.

.EXAMPLE
    .\EmailAuthChecker.ps1 -DomainList "microsoft.com,contoso.com,outlook.com"
    Analyze multiple domains.

.EXAMPLE
    .\EmailAuthChecker.ps1 -FilePath "C:\temp\domains.txt" -OutputPath "C:\reports" -AutoOpen
    Analyze domains from a file, save to specific directory, and auto-open the report.

.EXAMPLE
    .\EmailAuthChecker.ps1 -HeaderFilePath "C:\temp\headers.txt"
    Analyze domains extracted from email headers.

#>

[CmdletBinding()]
param(
    [Parameter(ParameterSetName = 'DomainList', Mandatory = $true)]
    [string[]]$DomainList,

    [Parameter(ParameterSetName = 'File', Mandatory = $true)]
    [string]$FilePath,

    [Parameter(ParameterSetName = 'Headers', Mandatory = $true)]
    [string]$HeaderFilePath,

    [Parameter(ParameterSetName = 'DomainList', Mandatory = $false)]
    [Parameter(ParameterSetName = 'File', Mandatory = $false)]
    [Parameter(ParameterSetName = 'Headers', Mandatory = $false)]
    [string]$OutputPath = ".",

    [Parameter(ParameterSetName = 'DomainList', Mandatory = $false)]
    [Parameter(ParameterSetName = 'File', Mandatory = $false)]
    [Parameter(ParameterSetName = 'Headers', Mandatory = $false)]
    [switch]$AutoOpen,

    [Parameter(ParameterSetName = 'DomainList', Mandatory = $false)]
    [Parameter(ParameterSetName = 'File', Mandatory = $false)]
    [Parameter(ParameterSetName = 'Headers', Mandatory = $false)]
    [switch]$SkipVersionCheck,

    [Parameter(Mandatory = $true, ParameterSetName = "ScriptUpdateOnly")]
    [switch]$ScriptUpdateOnly
)

# Function to get provider-specific documentation URLs
function Get-ProviderSpecificURLs {
    param([array]$Providers)

    # Check if Microsoft/Office 365 is in the providers list
    if ($Providers -contains "Microsoft/Office 365") {
        return @{
            SPFSetup         = "https://learn.microsoft.com/defender-office-365/email-authentication-spf-configure"
            SPFSyntax        = "https://learn.microsoft.com/defender-office-365/email-authentication-spf-configure#syntax-for-spf-txt-records"
            SPFMacroSecurity = "https://www.rfc-editor.org/rfc/rfc7208#section-7.2"
            DMARCSetup       = "https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure"
            DMARCReports     = "https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure#syntax-for-dmarc-txt-records"
            DKIMSetup        = "https://learn.microsoft.com/defender-office-365/email-authentication-dkim-configure"
        }
    } else {
        # Return default URLs for non-Microsoft providers
        return @{
            SPFSetup         = "https://www.rfc-editor.org/rfc/rfc7208"
            SPFSyntax        = "https://www.rfc-editor.org/rfc/rfc7208"
            SPFMacroSecurity = "https://www.rfc-editor.org/rfc/rfc7208#section-7.2"
            DMARCSetup       = "https://www.rfc-editor.org/rfc/rfc7489.html"
            DMARCReports     = "https://www.rfc-editor.org/rfc/rfc7489.html#section-7"
            DKIMSetup        = "https://www.rfc-editor.org/rfc/rfc6376"
        }
    }
}

# Enhanced UI Functions
# Helper function to parse DKIM records into key-value pairs
function ConvertFrom-DKIMRecord {
    param([string]$dkimRecord)

    $tags = @{}
    if ([string]::IsNullOrWhiteSpace($dkimRecord)) {
        return $tags
    }

    $parts = $dkimRecord -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }

    foreach ($part in $parts) {
        if ($part -match '^([a-z]+)=(.*)$') {
            $tagName = $matches[1].Trim()
            $tagValue = $matches[2].Trim()
            $tags[$tagName] = $tagValue
        }
    }

    return $tags
}

# Helper function to generate recommendations based on issue patterns
function Get-Recommendation {
    param(
        [string]$Issue,
        [string]$Protocol,
        [array]$Providers = @()
    )

    # Get provider-specific URLs
    $URLs = Get-ProviderSpecificURLs -Providers $Providers

    # Simplified approach - just return a generic recommendation for now
    switch ($Protocol) {
        "SPF" {
            if ($Issue -like "*+all*") {
                return "Fix SPF '+all' mechanism - Microsoft Guide: $($URLs.SPFSetup)"
            } elseif ($Issue -like "*'?all'*" -or $Issue -like "*Uses ?all*") {
                return "Strengthen SPF '?all' to '~all' or '-all' - Microsoft SPF Setup: $($URLs.SPFSyntax)"
            } elseif ($Issue -like "*all mechanism*") {
                return "Add proper 'all' mechanism to SPF record - Microsoft Documentation: $($URLs.SPFSetup)"
            } elseif ($Issue -like "*too long*" -or $Issue -like "*exceeds*") {
                return "Reduce SPF record length (max 255 chars) - Microsoft Best Practices: $($URLs.SPFSyntax)"
            } elseif ($Issue -like "*approaching*") {
                return "Consider optimizing SPF record length to avoid 255 character limit: $($URLs.SPFSyntax)"
            } elseif ($Issue -like "*DNS lookup limit*") {
                return "Optimize SPF record to reduce DNS lookups (max 10) - Consider flattening includes or using IP addresses - Microsoft SPF Optimization: $($URLs.SPFSyntax)"
            } elseif ($Issue -like "*Near DNS lookup limit*") {
                return "Consider optimizing SPF record to avoid DNS lookup limit: $($URLs.SPFSyntax)"
            } elseif ($Issue -like "*Syntax:*") {
                return "Fix SPF syntax errors - Microsoft SPF Syntax Guide: $($URLs.SPFSyntax)#spf-record-syntax"
            } elseif ($Issue -like "*Low TTL for domain*") {
                # Only show TTL recommendations for Microsoft/Office 365 providers
                if ($Providers -contains "Microsoft/Office 365") {
                    # Extract domain and TTL from the issue text
                    if ($Issue -match "Low TTL for domain (.+?) \((\d+) seconds\)") {
                        $domain = $matches[1]
                        $currentTTL = $matches[2]
                        # Check if TTL is less than 3600
                        if ([int]$currentTTL -lt 3600) {
                            return "Increase SPF record TTL for <strong>$domain</strong> from <strong>$currentTTL seconds</strong> to at least <strong>3600 seconds (1 hour)</strong> for better DNS caching and stability - Microsoft SPF Troubleshooting Guide: <a href='https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure?view=o365-worldwide#troubleshooting-spf-txt-records' target='_blank'>https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure?view=o365-worldwide#troubleshooting-spf-txt-records</a>"
                        } else {
                            return "Increase SPF record TTL to at least 3600 seconds (1 hour) for better DNS caching and stability - Microsoft SPF Troubleshooting Guide: <a href='https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure?view=o365-worldwide#troubleshooting-spf-txt-records' target='_blank'>https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure?view=o365-worldwide#troubleshooting-spf-txt-records</a>"
                        }
                    } else {
                        return "Increase SPF record TTL to at least 3600 seconds (1 hour) for better DNS caching and stability - Microsoft SPF Troubleshooting Guide: <a href='https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure?view=o365-worldwide#troubleshooting-spf-txt-records' target='_blank'>https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure?view=o365-worldwide#troubleshooting-spf-txt-records</a>"
                    }
                } else {
                    # Don't show TTL recommendations for non-Microsoft providers
                    return ""
                }
            } elseif ($Issue -like "*Low TTL*") {
                # Only show TTL recommendations for Microsoft/Office 365 providers
                if ($Providers -contains "Microsoft/Office 365") {
                    return "Increase SPF record TTL to at least 3600 seconds (1 hour) for better DNS caching and stability - Microsoft SPF Troubleshooting Guide: <a href='https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure?view=o365-worldwide#troubleshooting-spf-txt-records' target='_blank'>https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure?view=o365-worldwide#troubleshooting-spf-txt-records</a>"
                } else {
                    # Don't show TTL recommendations for non-Microsoft providers
                    return ""
                }
            } elseif ($Issue -like "*Multiple SPF records*") {
                return "Remove duplicate SPF records - Only one SPF record is allowed per domain (RFC 7208) $($URLs.SPFSyntax)"
            } elseif ($Issue -like "*Macro Security:*") {
                return "Review SPF macro usage and ensure to avoid complex macros that may expose infrastructure or create attack vectors $($URLs.SPFMacroSecurity)"
            } elseif ($Issue -like "*TTL Sub-Records:*") {
                # Only show TTL Sub-Records recommendations for Microsoft/Office 365 providers
                if ($Providers -contains "Microsoft/Office 365") {
                    return "Increase TTL for A/MX records referenced in SPF to at least 3600 seconds (1 hour) - Low TTL values can impact SPF validation performance and reliability - Microsoft SPF Troubleshooting Guide: <a href='https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure?view=o365-worldwide#troubleshooting-spf-txt-records' target='_blank'>https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure?view=o365-worldwide#troubleshooting-spf-txt-records</a>"
                } else {
                    # Don't show TTL recommendations for non-Microsoft providers
                    return ""
                }
            } else {
                return "Review SPF configuration - Microsoft SPF Guide: $($URLs.SPFSetup)"
            }
        }
        "DMARC" {
            if ($Issue -like "*reporting email*") {
                return "Configure DMARC reporting (rua/ruf) - Microsoft DMARC Reports: $($URLs.DMARCReports)"
            } elseif ($Issue -like "*subdomain policy*weaker*") {
                return "Strengthen subdomain policy to match or exceed main policy - Weak subdomain policies can be exploited - Microsoft DMARC Best Practices: $($URLs.DMARCSetup)"
            } elseif ($Issue -like "*Invalid*alignment*") {
                return "Fix DMARC alignment mode syntax - Valid values are 'r' (relaxed) or 's' (strict) - Microsoft DMARC Configuration: $($URLs.DMARCSetup)"
            } elseif ($Issue -like "*Invalid subdomain policy*") {
                return "Fix DMARC subdomain policy - Valid values are 'none', 'quarantine', or 'reject' - Microsoft DMARC Policies: $($URLs.DMARCSetup)"
            } elseif ($Issue -like "*Low TTL*") {
                # Only show TTL recommendations for Microsoft/Office 365 providers
                if ($Providers -contains "Microsoft/Office 365") {
                    # Extract domain and TTL from issue text
                    if ($Issue -match "Low TTL for domain ([^\s]+) \((\d+) seconds\)") {
                        $domain = $matches[1]
                        $currentTTL = $matches[2]
                        # Check if TTL is less than 3600
                        if ([int]$currentTTL -lt 3600) {
                            return "Increase DMARC record TTL for <strong>$domain</strong> from <strong>$currentTTL seconds</strong> to at least <strong>3600 seconds</strong> (1 hour) for better DNS caching and stability - Microsoft SPF Troubleshooting Guide: <a href='https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure?view=o365-worldwide#troubleshooting-spf-txt-records' target='_blank'>https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure?view=o365-worldwide#troubleshooting-spf-txt-records</a>"
                        } else {
                            return "Increase DMARC record TTL to at least 3600 seconds (1 hour) for better DNS caching and stability - Microsoft SPF Troubleshooting Guide: <a href='https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure?view=o365-worldwide#troubleshooting-spf-txt-records' target='_blank'>https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure?view=o365-worldwide#troubleshooting-spf-txt-records</a>"
                        }
                    } else {
                        return "Increase DMARC record TTL to at least 3600 seconds (1 hour) for better DNS caching and stability - Microsoft SPF Troubleshooting Guide: <a href='https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure?view=o365-worldwide#troubleshooting-spf-txt-records' target='_blank'>https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure?view=o365-worldwide#troubleshooting-spf-txt-records</a>"
                    }
                } else {
                    # Don't show TTL recommendations for non-Microsoft providers
                    return ""
                }
            }
        }
        "DKIM" {
            return "Fix DKIM syntax errors - Microsoft DKIM Configuration Guide: $($URLs.DKIMSetup)"
        }
        default {
            return "Review email authentication configuration - Microsoft Documentation"
        }
    }
}

# Function to analyze MX records for a domain
function Get-MXRecordAnalysis {
    param([string]$domain)

    $mxAnalysis = @{
        MXFound     = $false
        MXRecords   = @()
        MinTTL      = 0
        MaxTTL      = 0
        AverageTTL  = 0
        MXProviders = @()
        PrimaryMX   = ""
        BackupMX    = @()
    }

    if ([string]::IsNullOrWhiteSpace($domain)) {
        return $mxAnalysis
    }

    try {
        Write-Host "  [MX] Checking MX records..." -ForegroundColor White

        # Query MX records from authoritative servers for accuracy
        $authServers = Get-AuthoritativeDNSServers $domain
        $mxRecords = Resolve-DnsNameAuthoritative -Name $domain -Type MX -AuthoritativeServers $authServers

        if ($mxRecords -and $mxRecords.Count -gt 0) {
            $mxAnalysis.MXFound = $true
            $ttlValues = @()
            $priorities = @()

            # Sort MX records by priority
            $sortedMXRecords = $mxRecords | Sort-Object Preference

            foreach ($mxRecord in $sortedMXRecords) {
                if (-not [string]::IsNullOrWhiteSpace($mxRecord.NameExchange)) {
                    $mxInfo = @{
                        Server   = $mxRecord.NameExchange
                        Priority = $mxRecord.Preference
                        TTL      = $mxRecord.TTL
                    }

                    $mxAnalysis.MXRecords += $mxInfo
                    $ttlValues += $mxRecord.TTL
                    $priorities += $mxRecord.Preference

                    # Identify primary MX (lowest priority number)
                    if ([string]::IsNullOrWhiteSpace($mxAnalysis.PrimaryMX)) {
                        $mxAnalysis.PrimaryMX = $mxRecord.NameExchange
                    } elseif ($mxRecord.Preference -lt $priorities[0]) {
                        # Move current primary to backup
                        if ($mxAnalysis.PrimaryMX -notin $mxAnalysis.BackupMX) {
                            $mxAnalysis.BackupMX += $mxAnalysis.PrimaryMX
                        }
                        $mxAnalysis.PrimaryMX = $mxRecord.NameExchange
                    } else {
                        # Add to backup MX list
                        if ($mxRecord.NameExchange -ne $mxAnalysis.PrimaryMX) {
                            $mxAnalysis.BackupMX += $mxRecord.NameExchange
                        }
                    }

                    # Check for common email providers
                    $serverName = $mxRecord.NameExchange.ToLower()
                    $providerDetected = $false

                    if ($serverName -match "outlook|protection\.outlook\.com|mail\.protection\.outlook\.com") {
                        if ("Microsoft/Office 365" -notin $mxAnalysis.MXProviders) {
                            $mxAnalysis.MXProviders += "Microsoft/Office 365"
                        }
                        $providerDetected = $true
                    } elseif ($serverName -match "Gmail|Google|GoogleMail") {
                        if ("Google/Gmail" -notin $mxAnalysis.MXProviders) {
                            $mxAnalysis.MXProviders += "Google/Gmail"
                        }
                        $providerDetected = $true
                    } elseif ($serverName -match "AmazonSES|ses") {
                        if ("Amazon SES" -notin $mxAnalysis.MXProviders) {
                            $mxAnalysis.MXProviders += "Amazon SES"
                        }
                        $providerDetected = $true
                    } elseif ($serverName -match "Proofpoint|Pphosted") {
                        if ("Proofpoint" -notin $mxAnalysis.MXProviders) {
                            $mxAnalysis.MXProviders += "Proofpoint"
                        }
                        $providerDetected = $true
                    } elseif ($serverName -match "Mimecast") {
                        if ("Mimecast" -notin $mxAnalysis.MXProviders) {
                            $mxAnalysis.MXProviders += "Mimecast"
                        }
                        $providerDetected = $true
                    }

                    # Add Unknown provider if no known provider was detected
                    if (-not $providerDetected) {
                        if ("Unknown" -notin $mxAnalysis.MXProviders) {
                            $mxAnalysis.MXProviders += "Unknown"
                        }
                    }

                    # TTL validation can be added here if needed
                }
            }

            # Calculate TTL statistics
            if ($ttlValues.Count -gt 0) {
                $mxAnalysis.MinTTL = ($ttlValues | Measure-Object -Minimum).Minimum
                $mxAnalysis.MaxTTL = ($ttlValues | Measure-Object -Maximum).Maximum
                $mxAnalysis.AverageTTL = [math]::Round(($ttlValues | Measure-Object -Average).Average, 0)
            }

            # MX configuration validation can be added here if needed

            Write-Host "        MX records found: $($mxRecords.Count)" -ForegroundColor Green
            Write-Host "        Primary MX: $($mxAnalysis.PrimaryMX)" -ForegroundColor Cyan
            if ($mxAnalysis.BackupMX.Count -gt 0) {
                Write-Host "        Backup MX: $($mxAnalysis.BackupMX -join ', ')" -ForegroundColor Cyan
            }
            if ($mxAnalysis.MXProviders.Count -gt 0) {
                Write-Host "        Provider: $($mxAnalysis.MXProviders -join ', ')" -ForegroundColor Cyan
            }
        } else {
            Write-Host "        No MX records found" -ForegroundColor Red
        }
    } catch {
        Write-Host "        Error checking MX records: $($_.Exception.Message)" -ForegroundColor Red
    }

    return $mxAnalysis
}

# Function to count DNS lookups in SPF record
function Get-SpfDnsLookupCount {
    param([string]$spfRecord)

    $lookupCount = 0

    # Split SPF record into mechanisms
    $mechanisms = $spfRecord -split '\s+' | Where-Object { $_ -ne '' }

    foreach ($mechanism in $mechanisms) {
        # Count mechanisms that require DNS lookups or a mechanism without domain (uses current domain) or a/mx mechanisms with CIDR but no domain
        if ($mechanism -match '^(include:|a:|mx:|exists:|redirect=)' -or $mechanism -eq 'a' -or $mechanism -eq 'mx' -or $mechanism -match '^(a|mx)/\d+$') {
            $lookupCount++
        }
    }

    return $lookupCount
}

# Function to validate SPF record syntax
function Test-SPFSyntax {
    param([string]$spfRecord)

    Write-Verbose "Test-SPFSyntax: Calling $($MyInvocation.MyCommand): Processing spfRecord: '$spfRecord'"

    $syntaxIssues = @()

    # Check if record starts with v=spf1
    if (-not ($spfRecord -match '^v=spf1\b')) {
        $syntaxIssues += "Must start with 'v=spf1'"
        return $syntaxIssues  # If this fails, other checks may not be meaningful
    }

    # Split record into mechanisms and modifiers
    $mechanisms = $spfRecord -split '\s+' | Where-Object { $_ -ne '' -and $_ -ne 'v=spf1' }

    # Check for multiple 'all' mechanisms
    $allCount = ($mechanisms | Where-Object { $_ -match '^[+\-~?]?all$' }).Count
    if ($allCount -gt 1) {
        $syntaxIssues += "Multiple 'all' mechanisms found (only one allowed)"
    }

    # Validate each mechanism
    foreach ($mechanism in $mechanisms) {
        # Check for modifiers (contain '=')
        if ($mechanism -match '=' -and $mechanism -notmatch '^(include:|a:|mx:|ptr:|exists:|redirect=)') {
            # Check for unknown modifiers/mechanisms
            if ($mechanism -notmatch '^(exp=|redirect=)') {
                $syntaxIssues += "Unknown modifier or mechanism: '$mechanism'"
            }
        } elseif ($mechanism -match '^[+\-~?]?(all|include:|a|mx|ptr|exists:|ip4:|ip6:)') {
            # Valid mechanism types, check specific syntax
            if ($mechanism -match '^[+\-~?]?ip4:') {
                # Validate IPv4 address/CIDR
                $ipPart = $mechanism -replace '^[+\-~?]?ip4:', ''
                if (-not ($ipPart -match '^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$')) {
                    $syntaxIssues += "Invalid IPv4 syntax: '$mechanism'"
                }
            } elseif ($mechanism -match '^[+\-~?]?ip6:') {
                # Basic IPv6 validation (simplified)
                $ipPart = $mechanism -replace '^[+\-~?]?ip6:', ''
                if (-not ($ipPart -match '^[0-9a-fA-F:]+(/\d{1,3})?$')) {
                    $syntaxIssues += "Invalid IPv6 syntax: '$mechanism'"
                }
            } elseif ($mechanism -match '^[+\-~?]?include:') {
                # Validate include domain
                $domain = $mechanism -replace '^[+\-~?]?include:', ''
                if ([string]::IsNullOrEmpty($domain) -or $domain -match '\s') {
                    $syntaxIssues += "Invalid include syntax: '$mechanism'"
                }
            } elseif ($mechanism -match '^[+\-~?]?exists:') {
                # Validate exists domain
                $domain = $mechanism -replace '^[+\-~?]?exists:', ''
                if ([string]::IsNullOrEmpty($domain) -or $domain -match '\s') {
                    $syntaxIssues += "Invalid exists syntax: '$mechanism'"
                }
            }
        } else {
            # Unknown mechanism
            $syntaxIssues += "Unknown or invalid mechanism: '$mechanism'"
        }
    }

    # Check for 'all' mechanism (should be present)
    $hasAll = $mechanisms | Where-Object { $_ -match '^[+\-~?]?all$' }
    if (-not $hasAll) {
        $syntaxIssues += "Missing 'all' mechanism (recommended as last mechanism)"
    }

    # Check if 'all' is the last mechanism (best practice)
    if ($hasAll -and $mechanisms.Count -gt 1) {
        $lastMechanism = $mechanisms[-1]
        if ($lastMechanism -notmatch '^[+\-~?]?all$') {
            $syntaxIssues += "Recommend placing 'all' mechanism as the last mechanism"
        }
    }

    return $syntaxIssues
}

# Function to validate DKIM record syntax
function Test-DKIMSyntax {
    param([string]$dkimRecord, [string]$selector)

    Write-Verbose "Test-DKIMSyntax: Calling $($MyInvocation.MyCommand): Processing dkimRecord: '$dkimRecord' for selector '$selector'"

    $syntaxIssues = @()

    if ([string]::IsNullOrWhiteSpace($dkimRecord)) {
        $syntaxIssues += "Empty DKIM record"
        return $syntaxIssues
    }

    # Parse DKIM record using helper function
    $tags = ConvertFrom-DKIMRecord $dkimRecord

    if ($tags.Count -eq 0) {
        $syntaxIssues += "No valid DKIM tags found"
        return $syntaxIssues
    }

    # Check for invalid tag format in original record
    $parts = $dkimRecord -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
    foreach ($part in $parts) {
        if ($part -notmatch '^([a-z]+)=(.*)$') {
            $syntaxIssues += "Invalid tag format: '$part'"
        }
    }

    # Check required tags

    # 'v=' tag (version) - optional but recommended
    if ($tags.ContainsKey('v')) {
        if ($tags['v'] -ne 'DKIM1') {
            $syntaxIssues += "Invalid version: expected 'DKIM1', found '$($tags['v'])'"
        }
    }

    # 'k=' tag (key type) - optional, defaults to 'rsa'
    if ($tags.ContainsKey('k')) {
        $validKeyTypes = @('rsa', 'ed25519')
        if ($tags['k'] -notin $validKeyTypes) {
            $syntaxIssues += "Invalid key type: '$($tags['k'])' (valid: $($validKeyTypes -join ', '))"
        }
    }

    # 'p=' tag (public key) - required and must not be empty for active keys
    if (-not $tags.ContainsKey('p')) {
        $syntaxIssues += "Missing required 'p=' tag (public key)"
    } else {
        $publicKey = $tags['p']
        if ([string]::IsNullOrWhiteSpace($publicKey)) {
            # Empty p= tag indicates revoked key
            $syntaxIssues += "Empty public key (p=) - key is revoked"
        } else {
            # Basic Base64 validation for public key
            try {
                $cleanKey = $publicKey -replace '\s', ''
                if ($cleanKey -notmatch '^[A-Za-z0-9+/]*={0,2}$') {
                    $syntaxIssues += "Invalid Base64 format in public key"
                }
            } catch {
                $syntaxIssues += "Invalid public key format"
            }
        }
    }

    # 'h=' tag (hash algorithms) - optional
    if ($tags.ContainsKey('h')) {
        $validHashAlgorithms = @('sha1', 'sha256')
        $hashAlgorithms = $tags['h'] -split ':' | ForEach-Object { $_.Trim() }
        foreach ($hash in $hashAlgorithms) {
            if ($hash -notin $validHashAlgorithms) {
                $syntaxIssues += "Invalid hash algorithm: '$hash' (valid: $($validHashAlgorithms -join ', '))"
            }
        }
        # Recommend sha256 over sha1
        if ($hashAlgorithms -contains 'sha1' -and $hashAlgorithms -notcontains 'sha256') {
            $syntaxIssues += "Consider using 'sha256' instead of 'sha1' for better security"
        }
    }

    # 'g=' tag (granularity) - optional, deprecated
    if ($tags.ContainsKey('g')) {
        $syntaxIssues += "Granularity tag 'g=' is deprecated and should be removed"
    }

    # 's=' tag (service type) - optional
    if ($tags.ContainsKey('s')) {
        $validServiceTypes = @('email', '*')
        $serviceTypes = $tags['s'] -split ':' | ForEach-Object { $_.Trim() }
        foreach ($service in $serviceTypes) {
            if ($service -notin $validServiceTypes) {
                $syntaxIssues += "Invalid service type: '$service' (valid: $($validServiceTypes -join ', '))"
            }
        }
    }

    # 't=' tag (flags) - optional
    if ($tags.ContainsKey('t')) {
        $validFlags = @('y', 's')
        $flags = $tags['t'] -split ':' | ForEach-Object { $_.Trim() }
        foreach ($flag in $flags) {
            if ($flag -notin $validFlags) {
                $syntaxIssues += "Invalid flag: '$flag' (valid: $($validFlags -join ', '))"
            }
        }
        # Check for testing flag
        if ($flags -contains 'y') {
            $syntaxIssues += "Testing flag 'y' is set - remove for production use"
        }
    }

    # Check for unknown tags
    $knownTags = @('v', 'k', 'p', 'h', 'g', 's', 't', 'n')
    foreach ($tagName in $tags.Keys) {
        if ($tagName -notin $knownTags) {
            $syntaxIssues += "Unknown tag: '$tagName'"
        }
    }

    return $syntaxIssues
}

# Function to detect DKIM service providers
function Get-DKIMServiceProvider {
    param([hashtable]$dkimRecords, [string]$domain)

    $providerInfo = @{
        DetectedProviders = @()
        SelectorPatterns  = @()
        Details           = @()
    }

    # Common DKIM provider patterns
    $providerPatterns = @{
        'Microsoft/Office 365' = @('selector1', 'selector2')
        'Google/Gmail'         = @('Google', 'Gmail')
        'Amazon SES'           = @('AmazonSES')
        'Mailchimp'            = @('k1', 'k2', 'k3')
        'SendGrid'             = @('s1', 's2', 'smtpapi')
        'Constant Contact'     = @('k1', 'k2')
        'Mailgun'              = @('k1', 'mailo')
        'Mandrill'             = @('mandrill')
        'Postmark'             = @('pm', 'postmark')
        'SparkPost'            = @('scph')
        'Zendesk'              = @('Zendesk1', 'Zendesk2')
        'Salesforce'           = @('Salesforce')
        'HubSpot'              = @('hs1', 'hs2')
        'Klaviyo'              = @('dkim')
        'Campaign Monitor'     = @('cm')
        'AWeber'               = @('AWeber')
        'GetResponse'          = @('GetResponse')
        'ConvertKit'           = @('ConvertKit')
        'ActiveCampaign'       = @('ac')
        'Drip'                 = @('drip')
        'Infusionsoft'         = @('ifs')
        'Pardot'               = @('Pardot')
        'Marketo'              = @('Marketo')
        'Eloqua'               = @('Eloqua')
        'Braze'                = @('braze')
        'Iterable'             = @('iterable')
        'Sendlane'             = @('Sendlane')
        'Moosend'              = @('Moosend')
        'Omnisend'             = @('Omnisend')
        'Benchmark'            = @('benchmark')
        'EmailOctopus'         = @('EmailOctopus')
        'Sendinblue'           = @('Sendinblue')
        'Elastic Email'        = @('Elasticemail')
        'Pepipost'             = @('Pepipost')
        'Socketlabs'           = @('Socketlabs')
        'Mailjet'              = @('Mailjet')
        'SMTP2GO'              = @('smtp2go')
        'Turbo-SMTP'           = @('turbo-smtp')
        'Dynadot'              = @('Dynadot')
        'Zoho Mail'            = @('Zoho')
        'Titan Email'          = @('titan')
        'Protonmail'           = @('Protonmail')
        'Fastmail'             = @('fm1', 'fm2', 'fm3')
        'Rackspace'            = @('Rackspace')
        'Bluehost'             = @('default')
        'GoDaddy'              = @('k1')
        'Namecheap'            = @('default')
        'HostGator'            = @('default')
        'SiteGround'           = @('default')
        'cPanel'               = @('default')
        'Plesk'                = @('default')
        'Generic'              = @('default', 'mail', 'dkim', 'key1', 'key2')
    }

    foreach ($selector in $dkimRecords.Keys) {
        $selectorName = $selector.ToLower()
        $providerInfo.SelectorPatterns += $selectorName

        $matchedProvider = $null
        foreach ($provider in $providerPatterns.Keys) {
            $patterns = $providerPatterns[$provider]
            if ($patterns -contains $selectorName) {
                $matchedProvider = $provider
                break
            }
        }

        if ($matchedProvider) {
            if ($matchedProvider -notin $providerInfo.DetectedProviders) {
                $providerInfo.DetectedProviders += $matchedProvider
            }
            $providerInfo.Details += "Selector '$selector': Matches $matchedProvider pattern"
        } else {
            $providerInfo.Details += "Selector '$selector': Custom/Unknown provider"
        }
    }

    return $providerInfo
}

# Function to extract and analyze SPF all mechanism
function Get-SPFAllMechanism {
    param([string]$spfRecord)

    # Split SPF record into mechanisms
    $mechanisms = $spfRecord -split '\s+' | Where-Object { $_ -ne '' }

    # Find all mechanism
    $allMechanism = $mechanisms | Where-Object { $_ -match '^[+\-~?]?all$' } | Select-Object -Last 1

    if ($allMechanism) {
        return $allMechanism
    } else {
        return ""
    }
}

# Function to check for multiple SPF records (RFC violation)
function Test-MultipleSPFRecords {
    param([string]$domain)

    Write-Verbose "Test-MultipleSPFRecords: Calling $($MyInvocation.MyCommand): Processing domain: '$domain'"

    $multipleRecordIssues = @()

    try {
        # Get authoritative servers for the domain
        $authServers = Get-AuthoritativeDNSServers $domain
        $allTxtRecords = Resolve-DnsNameAuthoritative -Name $domain -Type TXT -AuthoritativeServers $authServers
        $spfRecords = $allTxtRecords | Where-Object { $_.Strings -like "v=spf*" }

        if ($spfRecords.Count -gt 1) {
            $multipleRecordIssues += "Multiple SPF records found - RFC 7208 violation (only one allowed)"
            for ($i = 0; $i -lt $spfRecords.Count; $i++) {
                $recordContent = $spfRecords[$i].Strings -join ""
                $multipleRecordIssues += "SPF Record $($i+1): $recordContent"
            }
        }
    } catch {
        $multipleRecordIssues += "Error checking for multiple SPF records: $($_.Exception.Message)"
    }

    return $multipleRecordIssues
}

# Function to validate SPF macros and check for security issues
function Test-SPFMacroSecurity {
    param([string]$spfRecord)

    Write-Verbose "Test-SPFMacroSecurity: Calling $($MyInvocation.MyCommand): Processing spfRecord: '$spfRecord'"

    $macroSecurityIssues = @()

    if ([string]::IsNullOrWhiteSpace($spfRecord)) {
        return $macroSecurityIssues
    }

    # Check for SPF macros (% followed by {})
    $macroMatches = [regex]::Matches($spfRecord, '%\{([^}]*)\}')

    if ($macroMatches.Count -eq 0) {
        # No macros found - this is good for security
        return $macroSecurityIssues
    }

    # Validate each macro for security and syntax
    foreach ($macroMatch in $macroMatches) {
        $fullMacro = $macroMatch.Value
        $macroContent = $macroMatch.Groups[1].Value

        # Parse macro components: letter[digits[r]][delimiter[...]]
        if ($macroContent -match '^([slodiptcrv])(\d+)?(r)?(\.[^}]*)?$') {
            $macroLetter = $matches[1]
            $digits = $matches[2]
            $reverse = $matches[3]
            $delimiter = $matches[4]

            # Check for potentially dangerous macro letters
            switch ($macroLetter) {
                'i' {
                    # IP address - generally safe but can reveal infrastructure
                    if ($digits -and [int]$digits -lt 16) {
                        $macroSecurityIssues += "Macro '$fullMacro' uses short IP truncation ($digits chars) - may not provide sufficient uniqueness"
                    }
                }
                'p' {
                    # PTR record - deprecated and slow, potential security risk
                    $macroSecurityIssues += "Macro '$fullMacro' uses PTR mechanism (deprecated) - can cause performance issues and DNS dependencies"
                }
                'c' {
                    # Client IP - can be spoofed in some contexts
                    $macroSecurityIssues += "Macro '$fullMacro' uses client IP validation - ensure this is intended and secure in your environment"
                }
                'r' {
                    # Domain name in reverse - complex processing
                    if (-not $reverse) {
                        $macroSecurityIssues += "Macro '$fullMacro' processes domain names - verify the source domain is trusted"
                    }
                }
                't' {
                    # Timestamp - can be manipulated
                    $macroSecurityIssues += "Macro '$fullMacro' uses timestamp validation - ensure time synchronization is reliable"
                }
            }

            # Check for overly complex delimiters
            if ($delimiter -and $delimiter.Length -gt 10) {
                $macroSecurityIssues += "Macro '$fullMacro' has complex delimiter '$delimiter' - review for necessity and security"
            }

            # Check for reverse processing combined with truncation
            if ($reverse -and $digits -and [int]$digits -lt 8) {
                $macroSecurityIssues += "Macro '$fullMacro' combines reverse processing with short truncation - may cause unexpected behavior"
            }
        } else {
            # Invalid macro syntax
            $macroSecurityIssues += "Invalid macro syntax: '$fullMacro' - does not match valid SPF macro format"
        }
    }

    # Check for macros in exists: mechanisms (often used for complex lookups)
    $existsWithMacros = [regex]::Matches($spfRecord, 'exists:[^%]*%\{[^}]*\}')
    if ($existsWithMacros.Count -gt 0) {
        $macroSecurityIssues += "Complex macro usage in exists: mechanism detected - review for security and necessity (can be used for data exfiltration)"
    }

    # Check for multiple macros in a single mechanism
    $mechanisms = $spfRecord -split '\s+' | Where-Object { $_ -ne '' -and $_ -ne 'v=spf1' }
    foreach ($mechanism in $mechanisms) {
        $mechanismMacros = [regex]::Matches($mechanism, '%\{[^}]*\}')
        if ($mechanismMacros.Count -gt 2) {
            $macroSecurityIssues += "Mechanism '$mechanism' contains $($mechanismMacros.Count) macros - excessive complexity may indicate security risk"
        }
    }

    # Overall macro count check
    if ($macroMatches.Count -gt 5) {
        $macroSecurityIssues += "SPF record contains $($macroMatches.Count) macros - high complexity increases attack surface and debugging difficulty"
    }

    return $macroSecurityIssues
}

# Function to check TTL for SPF sub-records (A records referenced in SPF)
function Test-SPFSubRecordsTTL {
    param([string]$spfRecord, [string]$domain)

    Write-Verbose "Test-SPFSubRecordsTTL: Calling $($MyInvocation.MyCommand): Processing spfRecord: '$spfRecord' for domain: '$domain'"

    $subRecordIssues = @()
    $checkedRecords = @()

    if ([string]::IsNullOrWhiteSpace($spfRecord)) {
        return $subRecordIssues
    }

    # Extract A record mechanisms from SPF record
    $mechanisms = $spfRecord -split '\s+' | Where-Object { $_ -ne '' -and $_ -ne 'v=spf1' }

    foreach ($mechanism in $mechanisms) {
        $domainToCheck = $null

        # Check for a: mechanisms with explicit domain
        if ($mechanism -match '^[+\-~?]?a:([^/\s]+)') {
            $domainToCheck = $matches[1]
        }
        # Check for a mechanism without domain (uses current domain)
        elseif ($mechanism -match '^[+\-~?]?a(/\d+)?$') {
            $domainToCheck = $domain
        }
        # Check for mx: mechanisms with explicit domain
        elseif ($mechanism -match '^[+\-~?]?mx:([^/\s]+)') {
            $domainToCheck = $matches[1]
        }
        # Check for mx mechanism without domain (uses current domain)
        elseif ($mechanism -match '^[+\-~?]?mx(/\d+)?$') {
            $domainToCheck = $domain
        }
        # Check for include: mechanisms (NEW - check TXT record TTL)
        elseif ($mechanism -match '^[+\-~?]?include:([^/\s]+)') {
            $includeDomain = $matches[1]

            # Skip if already checked
            if ($includeDomain -in $checkedRecords) {
                continue
            }

            $checkedRecords += $includeDomain

            try {
                # Check TXT records for the included domain against authoritative servers
                $authServers = Get-AuthoritativeDNSServers $includeDomain
                $txtRecords = Resolve-DnsNameAuthoritative -Name $includeDomain -Type TXT -AuthoritativeServers $authServers

                if ($txtRecords) {
                    foreach ($txtRecord in $txtRecords) {
                        # Only check SPF records (those starting with "v=spf1")
                        if ($txtRecord.Strings -match '^v=spf1\b') {
                            if ($txtRecord.TTL -lt 3600) {
                                $subRecordIssues += "TXT record (SPF) for include domain '$includeDomain' has low TTL ($($txtRecord.TTL) seconds) - recommend 3600+ seconds for stability"
                            }
                        }
                    }
                } else {
                    $subRecordIssues += "TXT record for include domain '$includeDomain' not found or inaccessible - SPF validation may fail"
                }
            } catch {
                $subRecordIssues += "Error checking TXT records for include domain '$includeDomain': $($_.Exception.Message)"
            }
            continue
        }

        # Skip if no domain to check or already checked
        if (-not $domainToCheck -or $domainToCheck -in $checkedRecords) {
            continue
        }

        $checkedRecords += $domainToCheck

        try {
            # Check A records for the domain against authoritative servers
            $authServers = Get-AuthoritativeDNSServers $domainToCheck
            $aRecords = Resolve-DnsNameAuthoritative -Name $domainToCheck -Type A -AuthoritativeServers $authServers

            if ($aRecords) {
                foreach ($aRecord in $aRecords) {
                    if ($aRecord.TTL -lt 3600) {
                        $subRecordIssues += "A record for '$domainToCheck' has low TTL ($($aRecord.TTL) seconds) - recommend 3600+ seconds for stability"
                    }
                }
            } else {
                $subRecordIssues += "A record for '$domainToCheck' not found or inaccessible - SPF validation may fail"
            }

            # Also check MX records if it's an MX mechanism
            if ($mechanism -match '^[+\-~?]?mx') {
                $mxAuthServers = Get-AuthoritativeDNSServers $domainToCheck
                $mxRecords = Resolve-DnsNameAuthoritative -Name $domainToCheck -Type MX -AuthoritativeServers $mxAuthServers

                if ($mxRecords) {
                    foreach ($mxRecord in $mxRecords) {
                        if ($mxRecord.TTL -lt 3600) {
                            $subRecordIssues += "MX record for '$domainToCheck' has low TTL ($($mxRecord.TTL) seconds) - recommend 3600+ seconds for stability"
                        }
                    }
                } else {
                    $subRecordIssues += "MX record for '$domainToCheck' not found or inaccessible - SPF validation may fail"
                }
            }
        } catch {
            $subRecordIssues += "Error checking records for '$domainToCheck': $($_.Exception.Message)"
        }
    }

    return $subRecordIssues
}

# Function to collect TTL values for SPF sub-records (A/MX/TXT records referenced in SPF)
function Get-SPFSubRecordsTTLValues {
    param([string]$spfRecord, [string]$domain)

    $subRecordTTLValues = @{}
    $checkedRecords = @()

    if ([string]::IsNullOrWhiteSpace($spfRecord)) {
        return $subRecordTTLValues
    }

    # Extract A record mechanisms from SPF record
    $mechanisms = $spfRecord -split '\s+' | Where-Object { $_ -ne '' -and $_ -ne 'v=spf1' }

    foreach ($mechanism in $mechanisms) {
        $domainToCheck = $null
        $recordType = ""

        # Check for a: mechanisms with explicit domain
        if ($mechanism -match '^[+\-~?]?a:([^/\s]+)') {
            $domainToCheck = $matches[1]
            $recordType = "A"
        }
        # Check for a mechanism without domain (uses current domain)
        elseif ($mechanism -match '^[+\-~?]?a(/\d+)?$') {
            $domainToCheck = $domain
            $recordType = "A"
        }
        # Check for mx: mechanisms with explicit domain
        elseif ($mechanism -match '^[+\-~?]?mx:([^/\s]+)') {
            $domainToCheck = $matches[1]
            $recordType = "MX"
        }
        # Check for mx mechanism without domain (uses current domain)
        elseif ($mechanism -match '^[+\-~?]?mx(/\d+)?$') {
            $domainToCheck = $domain
            $recordType = "MX"
        }
        # Check for include: mechanisms (NEW - collect TXT record TTL)
        elseif ($mechanism -match '^[+\-~?]?include:([^/\s]+)') {
            $includeDomain = $matches[1]

            # Skip if already checked
            if ($includeDomain -in $checkedRecords) {
                continue
            }

            $checkedRecords += $includeDomain

            try {
                # Check TXT records for the included domain against authoritative servers
                $authServers = Get-AuthoritativeDNSServers $includeDomain
                $txtRecords = Resolve-DnsNameAuthoritative -Name $includeDomain -Type TXT -AuthoritativeServers $authServers

                if ($txtRecords) {
                    $ttlValues = @()
                    foreach ($txtRecord in $txtRecords) {
                        # Only collect SPF records (those starting with "v=spf1")
                        if ($txtRecord.Strings -match '^v=spf1\b') {
                            $spfContent = ($txtRecord.Strings -join '')
                            $ttlValues += "${spfContent}: $($txtRecord.TTL)s"
                        }
                    }
                    if ($ttlValues.Count -gt 0) {
                        $subRecordTTLValues["$includeDomain (TXT-SPF)"] = $ttlValues -join ", "
                    }
                } else {
                    $subRecordTTLValues["$includeDomain (TXT-SPF Error)"] = "TXT record not found or inaccessible"
                }
            } catch {
                $subRecordTTLValues["$includeDomain (TXT-SPF Error)"] = "Unable to retrieve TTL: $($_.Exception.Message)"
            }
            continue
        }

        # Skip if no domain to check or already checked
        if (-not $domainToCheck -or $domainToCheck -in $checkedRecords) {
            continue
        }

        $checkedRecords += $domainToCheck

        try {
            # Check A records for the domain against authoritative servers
            if ($recordType -eq "A" -or $mechanism -match '^[+\-~?]?a') {
                $authServers = Get-AuthoritativeDNSServers $domainToCheck
                $aRecords = Resolve-DnsNameAuthoritative -Name $domainToCheck -Type A -AuthoritativeServers $authServers

                if ($aRecords) {
                    $ttlValues = @()
                    foreach ($aRecord in $aRecords) {
                        # Only add entries with valid IP addresses
                        if (-not [string]::IsNullOrWhiteSpace($aRecord.IPAddress)) {
                            $ttlValues += "$($aRecord.IPAddress): $($aRecord.TTL)s"
                        }
                    }
                    if ($ttlValues.Count -gt 0) {
                        $subRecordTTLValues["$domainToCheck (A)"] = $ttlValues -join ", "
                    }
                }
            }

            # Also check MX records if it's an MX mechanism
            if ($mechanism -match '^[+\-~?]?mx') {
                $mxAuthServers = Get-AuthoritativeDNSServers $domainToCheck
                $mxRecords = Resolve-DnsNameAuthoritative -Name $domainToCheck -Type MX -AuthoritativeServers $mxAuthServers

                if ($mxRecords) {
                    $ttlValues = @()
                    foreach ($mxRecord in $mxRecords) {
                        # Only add entries with valid NameExchange values
                        if (-not [string]::IsNullOrWhiteSpace($mxRecord.NameExchange)) {
                            $ttlValues += "$($mxRecord.NameExchange) (Priority: $($mxRecord.Preference)): $($mxRecord.TTL)s"
                        }
                    }
                    if ($ttlValues.Count -gt 0) {
                        $subRecordTTLValues["$domainToCheck (MX)"] = $ttlValues -join ", "
                    }
                }
            }
        } catch {
            $subRecordTTLValues["$domainToCheck (Error)"] = "Unable to retrieve TTL: $($_.Exception.Message)"
        }
    }

    return $subRecordTTLValues
}

# Function to extract DKIM key length from public key
function Get-DKIMKeyLength {
    param([string]$dkimRecord)

    if ([string]::IsNullOrWhiteSpace($dkimRecord)) {
        return @{
            KeyLength = 0
            KeyType   = "Unknown"
            IsWeak    = $false
            Error     = "No DKIM record provided"
        }
    }

    # Parse DKIM record using helper function
    $tags = ConvertFrom-DKIMRecord $dkimRecord

    # Get key type (default is RSA if not specified)
    $keyType = if ($tags.ContainsKey('k')) { $tags['k'] } else { "rsa" }

    # Check if key is revoked (empty p= tag)
    if ($tags.ContainsKey('p') -and [string]::IsNullOrWhiteSpace($tags['p'])) {
        return @{
            KeyLength = 0
            KeyType   = $keyType
            IsWeak    = $false
            Error     = "Key is revoked (empty p= tag)"
        }
    }

    # Get public key
    if (-not $tags.ContainsKey('p')) {
        return @{
            KeyLength = 0
            KeyType   = $keyType
            IsWeak    = $false
            Error     = "No public key (p=) tag found"
        }
    }

    $publicKey = $tags['p']
    if ([string]::IsNullOrWhiteSpace($publicKey)) {
        return @{
            KeyLength = 0
            KeyType   = $keyType
            IsWeak    = $false
            Error     = "Empty public key"
        }
    }

    try {
        # Clean the Base64 key (remove whitespace)
        $cleanKey = $publicKey -replace '\s', ''

        # Validate Base64 format
        if ($cleanKey -notmatch '^[A-Za-z0-9+/]*={0,2}$') {
            return @{
                KeyLength = 0
                KeyType   = $keyType
                IsWeak    = $false
                Error     = "Invalid Base64 format in public key"
            }
        }

        # Decode Base64 to get the DER-encoded key
        $keyBytes = [System.Convert]::FromBase64String($cleanKey)

        # For RSA keys, we need to parse the ASN.1 DER structure
        if ($keyType -eq "rsa") {
            # RSA public key in DER format starts with a sequence
            # We'll do a simplified parsing to extract the modulus length

            # Look for the RSA modulus (first large integer in the sequence)
            # This is a simplified approach - in a real implementation you'd use proper ASN.1 parsing

            # The modulus typically starts after the algorithm identifier
            # We'll search for large byte sequences that likely represent the modulus
            $keyLength = 0

            # Look for typical RSA key patterns
            # 1024-bit keys typically have modulus around 128 bytes (256 hex chars)
            # 2048-bit keys typically have modulus around 256 bytes (512 hex chars)
            # 4096-bit keys typically have modulus around 512 bytes (1024 hex chars)

            $keyLength = switch ($keyBytes.Length) {
                { $_ -ge 512 -and $_ -lt 768 } { 4096 }  # 4096-bit key
                { $_ -ge 294 -and $_ -lt 512 } { 2048 }  # 2048-bit key
                { $_ -ge 162 -and $_ -lt 294 } { 1024 }  # 1024-bit key
                { $_ -ge 94 -and $_ -lt 162 } { 512 }    # 512-bit key (very weak)
                default {
                    # Try to estimate based on total key size
                    $estimatedBits = [math]::Round(($keyBytes.Length - 30) * 8 / 1.2, 0)
                    if ($estimatedBits -gt 4096) { 4096 }
                    elseif ($estimatedBits -gt 2048) { 2048 }
                    elseif ($estimatedBits -gt 1024) { 1024 }
                    elseif ($estimatedBits -gt 512) { 512 }
                    else { $estimatedBits }
                }
            }

            $isWeak = $keyLength -lt 1024  # Only keys below 1024 are considered weak

            return @{
                KeyLength = $keyLength
                KeyType   = $keyType
                IsWeak    = $isWeak
                Error     = $null
            }
        } elseif ($keyType -eq "ed25519") {
            # Ed25519 keys are always 256 bits (32 bytes for the public key)
            return @{
                KeyLength = 256
                KeyType   = $keyType
                IsWeak    = $false  # Ed25519 is considered secure
                Error     = $null
            }
        } else {
            return @{
                KeyLength = 0
                KeyType   = $keyType
                IsWeak    = $false
                Error     = "Unsupported key type: $keyType"
            }
        }
    } catch {
        return @{
            KeyLength = 0
            KeyType   = $keyType
            IsWeak    = $false
            Error     = "Failed to parse public key: $($_.Exception.Message)"
        }
    }
}

# Helper function to get DKIM key status
function Get-DKIMKeyStatus {
    param([string]$dkimRecord)

    if ([string]::IsNullOrWhiteSpace($dkimRecord)) {
        return "N/A"
    }

    $tags = ConvertFrom-DKIMRecord $dkimRecord

    # Check if this is a revoked key (empty p= tag)
    if ($tags.ContainsKey('p') -and [string]::IsNullOrWhiteSpace($tags['p'])) {
        return "REVOKED"
    }

    # Check for testing flag
    if ($tags.ContainsKey('t') -and $tags['t'] -match 'y') {
        return "TESTING"
    }

    # Check for active key with valid public key
    if ($tags.ContainsKey('p') -and -not [string]::IsNullOrWhiteSpace($tags['p'])) {
        return "ACTIVE"
    }

    return "UNKNOWN"
}

# Function to get authoritative DNS servers and their IP addresses for a domain
function Get-AuthoritativeDNSServers {
    param([string]$domain)

    $authServers = @()

    try {
        # Get NS records for the domain
        $nsRecords = Resolve-DnsName -Name $domain -Type NS -ErrorAction SilentlyContinue

        if ($nsRecords) {
            foreach ($ns in $nsRecords) {
                if ($ns.Type -eq "NS") {
                    try {
                        # Resolve IP address of NS server
                        $nsIP = (Resolve-DnsName -Name $ns.NameHost -Type A -ErrorAction SilentlyContinue)[0].IPAddress
                        if ($nsIP) {
                            $authServers += [PSCustomObject]@{
                                NameHost  = $ns.NameHost
                                IPAddress = $nsIP
                            }
                        }
                    } catch {
                        Write-Verbose "Could not resolve IP for NS server $($ns.NameHost): $_"
                    }
                }
            }
        }

        # If no NS records found for the domain, try the parent domain
        if ($authServers.Count -eq 0 -and $domain.Contains('.')) {
            $parentDomain = $domain.Substring($domain.IndexOf('.') + 1)
            $parentNS = Resolve-DnsName -Name $parentDomain -Type NS -ErrorAction SilentlyContinue

            if ($parentNS) {
                foreach ($ns in $parentNS) {
                    if ($ns.Type -eq "NS") {
                        try {
                            $nsIP = (Resolve-DnsName -Name $ns.NameHost -Type A -ErrorAction SilentlyContinue)[0].IPAddress
                            if ($nsIP) {
                                $authServers += [PSCustomObject]@{
                                    NameHost  = $ns.NameHost
                                    IPAddress = $nsIP
                                }
                            }
                        } catch {
                            Write-Verbose "Could not resolve IP for parent NS server $($ns.NameHost): $_"
                        }
                    }
                }
            }
        }
    } catch {
        Write-Verbose "Error finding authoritative servers for $domain`: $_"
    }

    return $authServers
}

# Function to perform DNS query against authoritative servers
function Resolve-DnsNameAuthoritative {
    param(
        [string]$Name,
        [string]$Type,
        [array]$AuthoritativeServers = @()
    )

    $results = @()

    # If no authoritative servers provided, find them
    if ($AuthoritativeServers.Count -eq 0) {
        $domain = $Name
        # Extract domain from subdomain queries like _dmarc.example.com or selector1._domainkey.example.com
        if ($Name.Contains('.')) {
            $parts = $Name -split '\.'
            if ($parts.Count -gt 2) {
                # For DKIM records like selector1._domainkey.example.com, extract example.com
                if ($Name -match '_domainkey\.(.+)$') {
                    $domain = $matches[1]
                }
                # For DMARC records like _dmarc.example.com, extract example.com
                elseif ($Name -match '^_dmarc\.(.+)$') {
                    $domain = $matches[1]
                }
                # For other subdomains, try the main domain
                else {
                    $domain = ($parts[-2..-1]) -join '.'
                }
            }
        }
        $AuthoritativeServers = Get-AuthoritativeDNSServers $domain
    }

    # If we have authoritative servers, query them directly
    if ($AuthoritativeServers.Count -gt 0) {
        foreach ($server in $AuthoritativeServers) {
            try {
                Write-Verbose "Querying authoritative server: $($server.NameHost) ($($server.IPAddress)) for $Name ($Type)"
                # Query using the IP address of the authoritative server
                $result = Resolve-DnsName -Name $Name -Type $Type -Server $server.IPAddress -ErrorAction SilentlyContinue
                if ($result) {
                    $results += $result
                    Write-Verbose "Successfully retrieved $($result.Count) records from $($server.NameHost)"
                    break  # Use first successful result
                }
            } catch {
                Write-Verbose "Failed to query $($server.NameHost) ($($server.IPAddress)) for $Name`: $_"
                continue
            }
        }
    }

    # Fallback to regular DNS query if authoritative query fails
    if ($results.Count -eq 0) {
        try {
            Write-Verbose "Falling back to regular DNS query for $Name ($Type)"
            $results = Resolve-DnsName -Name $Name -Type $Type -ErrorAction SilentlyContinue
        } catch {
            Write-Verbose "Regular DNS query also failed for $Name`: $_"
        }
    }

    return $results
}

# Function to validate domain name format
function Test-DomainFormat {
    param(
        [string]$DomainName,
        [string]$Context = "domain"
    )

    Write-Verbose "Test-DomainFormat: Calling $($MyInvocation.MyCommand): Processing domain: '$DomainName' in context: '$Context'"

    # Check for invalid characters based on context
    $invalidChars = @()

    if ($Context -eq "single") {
        # For single domain analysis, comma and semicolon are not allowed
        $invalidChars = @(',', ';')
        $invalidPattern = '[,;]'
    } elseif ($Context -eq "multiple") {
        # For multiple domain analysis, semicolon, backslash, and forward slash are not allowed
        $invalidChars = @(';', '\', '/')
        $invalidPattern = '[;\\\/]'
    }

    # Check for invalid characters
    if ($DomainName -match $invalidPattern) {
        $foundChars = @()
        foreach ($char in $invalidChars) {
            if ($DomainName.Contains($char)) {
                $foundChars += "'$char'"
            }
        }

        Write-Host ""
        Write-Host "ERROR: Invalid characters detected in domain input!" -ForegroundColor Red
        Write-Host "Found invalid character(s): $($foundChars -join ', ')" -ForegroundColor Yellow

        if ($Context -eq "single") {
            Write-Host ""
            Write-Host "For Single Domain Analysis:" -ForegroundColor Cyan
            Write-Host "  - Use only valid domain characters (letters, numbers, dots, hyphens)" -ForegroundColor White
            Write-Host "  - Example: example.com" -ForegroundColor Green
            Write-Host "  - Do NOT use commas (,) or semicolons (;)" -ForegroundColor Red
            Write-Host ""
            Write-Host "If you want to analyze multiple domains, please select option [2] instead." -ForegroundColor Yellow
            Write-Host "Or if you have email headers with domain information, select option [4]." -ForegroundColor Yellow
        } elseif ($Context -eq "multiple") {
            Write-Host ""
            Write-Host "For Multiple Domain Analysis:" -ForegroundColor Cyan
            Write-Host "  - Separate domains with commas (,) only" -ForegroundColor White
            Write-Host "  - Example: example.com,contoso.com,microsoft.com" -ForegroundColor Green
            Write-Host "  - Do NOT use semicolons (;), backslashes (\), or forward slashes (/)" -ForegroundColor Red
        }

        Write-Host ""
        Write-Host "Please restart the script and enter valid domain names." -ForegroundColor Yellow
        Write-Host "============================================" -ForegroundColor Cyan
        return $false
    }

    return $true
}

# Function to analyze Authentication-Results for DMARC Pass check
function Get-AuthenticationResults {
    param([string]$HeaderContent)

    $authResults = @{
        SPFResult                       = "Unknown"
        DKIMResult                      = "Unknown"
        DMARCResult                     = "Unknown"
        Action                          = ""
        SMTPMailFrom                    = ""
        HeaderFrom                      = ""
        HeaderD                         = ""
        CompAuth                        = ""
        Reason                          = ""
        AuthenticationResultsRaw        = ""
        DMARCPass                       = "No"
        Condition1Met                   = $false
        Condition2Met                   = $false
        Details                         = @()
        AntispamMailboxDelivery         = ""
        AntispamUCF                     = ""
        AntispamJMR                     = ""
        AntispamDest                    = ""
        AntispamOFR                     = ""
        Office365FilteringCorrelationId = ""
        ForefrontAntispamReport         = ""
        ForefrontCIP                    = ""
        ForefrontCTRY                   = ""
        ForefrontLANG                   = ""
        ForefrontSCL                    = ""
        ForefrontSRV                    = ""
        ForefrontIPV                    = ""
        ForefrontSFV                    = ""
        ForefrontPTR                    = ""
        ForefrontCAT                    = ""
        ForefrontDIR                    = ""
        ForefrontSFP                    = ""
    }

    # Parse Authentication-Results header for individual components
    # Enhanced regex to capture only Authentication-Results headers that start with spf= and end with reason=
    # This excludes ARC-Authentication-Results and other unwanted headers
    $authResultsMatches = [regex]::Matches($HeaderContent, '(?<!ARC-)Authentication-Results:\s*(spf=.*?reason=[^\r\n]*)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::SingleLine)

    foreach ($match in $authResultsMatches) {
        $authFullHeader = $match.Groups[0].Value  # Complete header including "Authentication-Results:"
        $authLine = $match.Groups[1].Value        # Just the content after "Authentication-Results:"

        # Store the complete Authentication-Results header
        if ([string]::IsNullOrEmpty($authResults.AuthenticationResultsRaw)) {
            $authResults.AuthenticationResultsRaw = $authFullHeader.Trim()
        } else {
            $authResults.AuthenticationResultsRaw += "`r`n" + $authFullHeader.Trim()
        }

        $authResults.Details += "Found Authentication-Results: $($authLine.Trim())"

        # Extract SPF result - improved to handle parenthetical info
        if ($authLine -match 'spf=([a-zA-Z]+)(?:\s*\([^)]*\))?') {
            $authResults.SPFResult = $matches[1].ToLower()
            $authResults.Details += "SPF Result: $($authResults.SPFResult)"
        }

        # Extract DKIM result - improved to handle parenthetical info
        if ($authLine -match 'dkim=([a-zA-Z]+)(?:\s*\([^)]*\))?') {
            $authResults.DKIMResult = $matches[1].ToLower()
            $authResults.Details += "DKIM Result: $($authResults.DKIMResult)"
        }

        # Extract DMARC result - improved to handle action and other parameters
        if ($authLine -match 'dmarc=([a-zA-Z]+)(?:\s*(?:action=([a-zA-Z]+))?)?') {
            $authResults.DMARCResult = $matches[1].ToLower()
            $authResults.Details += "DMARC Result: $($authResults.DMARCResult)"
            if ($matches[2]) {
                $authResults.Action = $matches[2].ToLower()
                $authResults.Details += "DMARC Action: $($matches[2])"
            }
        }

        # Extract smtp.mailfrom
        if ($authLine -match 'smtp\.mailfrom=([^;\s\r\n]+)') {
            $smtpDomain = $matches[1].Trim() -replace '^["\''<\[\(]', '' -replace '["\''>\]\);,]$', ''
            $authResults.SMTPMailFrom = $smtpDomain
            $authResults.Details += "Mail From (P1): $smtpDomain"
        }

        # Extract header.from
        if ($authLine -match 'header\.from=([^;\s\r\n]+)') {
            $headerFromDomain = $matches[1].Trim() -replace '^["\''<\[\(]', '' -replace '["\''>\]\);,]$', ''
            $authResults.HeaderFrom = $headerFromDomain
            $authResults.Details += "From (P2): $headerFromDomain"
        }

        # Extract header.d (for DKIM)
        if ($authLine -match 'header\.d=([^;\s\r\n]+)') {
            $headerDDomain = $matches[1].Trim() -replace '^["\''<\[\(]', '' -replace '["\''>\]\);,]$', ''
            $authResults.HeaderD = $headerDDomain
            $authResults.Details += "Header.d: $headerDDomain"
        }

        # Extract compauth
        if ($authLine -match 'compauth=([^;\s\r\n]+)') {
            $compAuthValue = $matches[1].Trim() -replace '^["\''<\[\(]', '' -replace '["\''>\]\);,]$', ''
            $authResults.CompAuth = $compAuthValue
            $authResults.Details += "CompAuth: $compAuthValue"
        }

        # Extract reason
        if ($authLine -match 'reason=([^;\s\r\n]+)') {
            $reasonValue = $matches[1].Trim() -replace '^["\''<\[\(]', '' -replace '["\''>\]\);,]$', ''
            $authResults.Reason = $reasonValue
            $authResults.Details += "Reason: $reasonValue"
        }
    }

    # Check DMARC Pass conditions
    $condition1Met = $false
    $condition2Met = $false

    # Condition 1: spf=pass AND header.from matches smtp.mailfrom
    if ($authResults.SPFResult -eq "pass" -and
        -not [string]::IsNullOrEmpty($authResults.HeaderFrom) -and
        -not [string]::IsNullOrEmpty($authResults.SMTPMailFrom) -and
        $authResults.HeaderFrom.ToLower() -eq $authResults.SMTPMailFrom.ToLower()) {
        $condition1Met = $true
        $authResults.Condition1Met = $true
        $authResults.Details += "DMARC Pass Condition 1 MET: SPF=pass AND header.from ($($authResults.HeaderFrom)) matches smtp.mailfrom ($($authResults.SMTPMailFrom))"
    } else {
        $authResults.Condition1Met = $false
    }

    # Condition 2: dkim=pass AND header.d matches smtp.mailfrom
    if ($authResults.DKIMResult -eq "pass" -and
        -not [string]::IsNullOrEmpty($authResults.HeaderD) -and
        -not [string]::IsNullOrEmpty($authResults.SMTPMailFrom) -and
        $authResults.HeaderD.ToLower() -eq $authResults.SMTPMailFrom.ToLower()) {
        $condition2Met = $true
        $authResults.Condition2Met = $true
        $authResults.Details += "DMARC Pass Condition 2 MET: DKIM=pass AND header.d ($($authResults.HeaderD)) matches smtp.mailfrom ($($authResults.SMTPMailFrom))"
    } else {
        $authResults.Condition2Met = $false
    }

    # Set DMARC Pass result
    if ($condition1Met -or $condition2Met) {
        $authResults.DMARCPass = "Yes"
        $authResults.Details += "DMARC Pass: YES (at least one condition met)"
    } else {
        $authResults.DMARCPass = "No"
        $authResults.Details += "DMARC Pass: NO (no conditions met)"

        # Add detailed explanation why conditions weren't met
        if ($authResults.SPFResult -ne "pass") {
            $authResults.Details += "Condition 1 failed: SPF result is '$($authResults.SPFResult)' (needs 'pass')"
        }
        if ($authResults.DKIMResult -ne "pass") {
            $authResults.Details += "Condition 2 failed: DKIM result is '$($authResults.DKIMResult)' (needs 'pass')"
        }
        if ([string]::IsNullOrEmpty($authResults.HeaderFrom) -or [string]::IsNullOrEmpty($authResults.SMTPMailFrom)) {
            $authResults.Details += "Condition 1 failed: Missing header.from or smtp.mailfrom values"
        } elseif ($authResults.HeaderFrom.ToLower() -ne $authResults.SMTPMailFrom.ToLower()) {
            $authResults.Details += "Condition 1 failed: header.from ($($authResults.HeaderFrom)) doesn't match smtp.mailfrom ($($authResults.SMTPMailFrom))"
        }
        if ([string]::IsNullOrEmpty($authResults.HeaderD) -or [string]::IsNullOrEmpty($authResults.SMTPMailFrom)) {
            $authResults.Details += "Condition 2 failed: Missing header.d or smtp.mailfrom values"
        } elseif ($authResults.HeaderD.ToLower() -ne $authResults.SMTPMailFrom.ToLower()) {
            $authResults.Details += "Condition 2 failed: header.d ($($authResults.HeaderD)) doesn't match smtp.mailfrom ($($authResults.SMTPMailFrom))"
        }
    }

    # Parse X-Microsoft-Antispam-Mailbox-Delivery header
    # Enhanced regex to capture complete multi-line X-Microsoft-Antispam-Mailbox-Delivery header
    $antiSpamMatches = [regex]::Matches($HeaderContent, 'X-Microsoft-Antispam-Mailbox-Delivery:\s*([^\r\n]*(?:\r?\n\s+[^\r\n]*)*)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Multiline)

    if ($antiSpamMatches.Count -gt 0) {
        # Take the first match and get the complete header value
        $antiSpamValue = $antiSpamMatches[0].Groups[1].Value
        # Clean up the value by removing extra whitespace and line breaks
        $cleanedValue = $antiSpamValue -replace '\r?\n\s*', ' ' -replace '\s+', ' '
        $authResults.AntispamMailboxDelivery = $cleanedValue.Trim()
        $authResults.Details += "Found X-Microsoft-Antispam-Mailbox-Delivery header"

        # Parse individual parameters from the cleaned value
        $cleanedValue = $authResults.AntispamMailboxDelivery

        # Extract UCF (Unified Content Filter)
        if ($cleanedValue -match 'ucf:(\d+)') {
            $authResults.AntispamUCF = $matches[1]
        }

        # Extract JMR (Junk Mail Rule)
        if ($cleanedValue -match 'jmr:(\d+)') {
            $authResults.AntispamJMR = $matches[1]
        }

        # Extract dest (Destination)
        if ($cleanedValue -match 'dest:([^;]+)') {
            $authResults.AntispamDest = $matches[1]
        }

        # Extract OFR (Organizational Filtering Rules)
        if ($cleanedValue -match 'OFR:([^;]+)') {
            $authResults.AntispamOFR = $matches[1]
        }
    }

    # Parse X-MS-Office365-Filtering-Correlation-Id header
    $office365FilteringMatches = [regex]::Matches($HeaderContent, 'X-MS-Office365-Filtering-Correlation-Id:\s*([^\r\n]+)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    if ($office365FilteringMatches.Count -gt 0) {
        # Take the first match and get the correlation ID value
        $correlationIdValue = $office365FilteringMatches[0].Groups[1].Value.Trim()
        $authResults.Office365FilteringCorrelationId = $correlationIdValue
        $authResults.Details += "Found X-MS-Office365-Filtering-Correlation-Id header"
    }

    # Parse X-Forefront-Antispam-Report-Untrusted header
    # Enhanced regex to capture complete multi-line X-Forefront-Antispam-Report-Untrusted header
    $forefrontMatches = [regex]::Matches($HeaderContent, 'X-Forefront-Antispam-Report-Untrusted:\s*([^\r\n]*(?:\r?\n\s+[^\r\n]*)*)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Multiline)

    if ($forefrontMatches.Count -gt 0) {
        # Take the first match and get the complete header value
        $forefrontValue = $forefrontMatches[0].Groups[1].Value
        # Clean up the value by removing extra whitespace and line breaks
        $cleanedForefrontValue = $forefrontValue -replace '\r?\n\s*', ' ' -replace '\s+', ' '
        $authResults.ForefrontAntispamReport = $cleanedForefrontValue.Trim()
        $authResults.Details += "Found X-Forefront-Antispam-Report-Untrusted header"

        # Parse individual parameters from the cleaned value
        $cleanedForefrontValue = $authResults.ForefrontAntispamReport

        # Extract CIP (Client IP)
        if ($cleanedForefrontValue -match 'CIP:([^;]+)') {
            $authResults.ForefrontCIP = $matches[1]
        }

        # Extract CTRY (Country)
        if ($cleanedForefrontValue -match 'CTRY:([^;]*)') {
            $authResults.ForefrontCTRY = $matches[1]
        }

        # Extract LANG (Language)
        if ($cleanedForefrontValue -match 'LANG:([^;]+)') {
            $authResults.ForefrontLANG = $matches[1]
        }

        # Extract SCL (Spam Confidence Level)
        if ($cleanedForefrontValue -match 'SCL:([^;]+)') {
            $authResults.ForefrontSCL = $matches[1]
        }

        # Extract SRV (Service)
        if ($cleanedForefrontValue -match 'SRV:([^;]*)') {
            $authResults.ForefrontSRV = $matches[1]
        }

        # Extract IPV (IP Version)
        if ($cleanedForefrontValue -match 'IPV:([^;]+)') {
            $authResults.ForefrontIPV = $matches[1]
        }

        # Extract SFV (Sender Filter Verdict)
        if ($cleanedForefrontValue -match 'SFV:([^;]+)') {
            $authResults.ForefrontSFV = $matches[1]
        }

        # Extract PTR (Reverse DNS)
        if ($cleanedForefrontValue -match 'PTR:([^;]*)') {
            $authResults.ForefrontPTR = $matches[1]
        }

        # Extract CAT (Category)
        if ($cleanedForefrontValue -match 'CAT:([^;]+)') {
            $authResults.ForefrontCAT = $matches[1]
        }

        # Extract DIR (Direction)
        if ($cleanedForefrontValue -match 'DIR:([^;]+)') {
            $authResults.ForefrontDIR = $matches[1]
        }

        # Extract SFP (Sender Filter Policy)
        if ($cleanedForefrontValue -match 'SFP:([^;]+)') {
            $authResults.ForefrontSFP = $matches[1]
        }
    }

    return $authResults
}

# Function to parse email headers and extract domains from smtp.mailfrom and header.from
function Get-DomainsFromEmailHeaders {
    param([string]$FilePath)

    $domains = @()
    $foundEntries = @()

    if (-not (Test-Path -Path $FilePath)) {
        Write-Host "Email header file not found: $FilePath" -ForegroundColor Red
        return @()
    }

    try {
        $headerContent = Get-Content -Path $FilePath -ErrorAction Stop -Raw

        Write-Host "Parsing email headers from: $FilePath" -ForegroundColor Cyan
        Write-Host "File size: $($headerContent.Length) characters" -ForegroundColor Gray
        Write-Host ""

        # Analyze Authentication-Results for DMARC Pass check
        Write-Host "=== AUTHENTICATION RESULTS ANALYSIS ===" -ForegroundColor Yellow
        $authResults = Get-AuthenticationResults -HeaderContent $headerContent

        # Store authentication results at script scope for later use
        $script:AuthenticationResults = $authResults

        Write-Host "SPF Result: $($authResults.SPFResult)" -ForegroundColor $(if ($authResults.SPFResult -eq 'pass') { 'Green' }else { 'Red' })
        Write-Host "DKIM Result: $($authResults.DKIMResult)" -ForegroundColor $(if ($authResults.DKIMResult -eq 'pass') { 'Green' }else { 'Red' })
        Write-Host "DMARC Result: $($authResults.DMARCResult)" -ForegroundColor $(if ($authResults.DMARCResult -eq 'pass') { 'Green' }else { 'Red' })
        Write-Host "Mail From (P1): $($authResults.SMTPMailFrom)" -ForegroundColor Cyan
        Write-Host "From (P2): $($authResults.HeaderFrom)" -ForegroundColor Cyan
        Write-Host "Header.d: $($authResults.HeaderD)" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "DMARC PASS CHECK: $($authResults.DMARCPass)" -ForegroundColor $(if ($authResults.DMARCPass -eq 'Yes') { 'Green' }else { 'Red' }) -BackgroundColor $(if ($authResults.DMARCPass -eq 'Yes') { 'DarkGreen' }else { 'DarkRed' })
        Write-Host ""
        Write-Host "DMARC Pass Explanation:" -ForegroundColor Cyan
        Write-Host "  This check determines if the email would pass DMARC authentication based on:" -ForegroundColor White
        Write-Host ""

        # Enhanced condition display with status indicators
        Write-Host "  DMARC Pass Conditions:" -ForegroundColor Yellow

        # Condition 1 with status
        $condition1Status = if ($authResults.Condition1Met) { "[PASS] MET" } else { "[FAIL] NOT MET" }
        $condition1Color = if ($authResults.Condition1Met) { "Green" } else { "Red" }
        $condition1BgColor = if ($authResults.Condition1Met) { "DarkGreen" } else { "DarkRed" }

        Write-Host "    [$condition1Status]" -ForegroundColor $condition1Color -BackgroundColor $condition1BgColor -NoNewline
        Write-Host " Condition 1: SPF=pass AND header.from matches smtp.mailfrom" -ForegroundColor White

        if ($authResults.Condition1Met) {
            Write-Host "      [PASS] SPF Result: $($authResults.SPFResult)" -ForegroundColor Green
            Write-Host "      [PASS] header.from ($($authResults.HeaderFrom)) = smtp.mailfrom ($($authResults.SMTPMailFrom))" -ForegroundColor Green
        } else {
            Write-Host "      [FAIL] SPF Result: $($authResults.SPFResult)" -ForegroundColor Red
            if ($authResults.HeaderFrom -and $authResults.SMTPMailFrom) {
                if ($authResults.HeaderFrom.ToLower() -eq $authResults.SMTPMailFrom.ToLower()) {
                    Write-Host "      [PASS] header.from ($($authResults.HeaderFrom)) = smtp.mailfrom ($($authResults.SMTPMailFrom))" -ForegroundColor Green
                } else {
                    Write-Host "      [FAIL] header.from ($($authResults.HeaderFrom)) != smtp.mailfrom ($($authResults.SMTPMailFrom))" -ForegroundColor Red
                }
            } else {
                Write-Host "      [FAIL] Missing domain values" -ForegroundColor Red
            }
        }
        Write-Host ""

        # Condition 2 with status
        $condition2Status = if ($authResults.Condition2Met) { "[PASS] MET" } else { "[FAIL] NOT MET" }
        $condition2Color = if ($authResults.Condition2Met) { "Green" } else { "Red" }
        $condition2BgColor = if ($authResults.Condition2Met) { "DarkGreen" } else { "DarkRed" }

        Write-Host "    [$condition2Status]" -ForegroundColor $condition2Color -BackgroundColor $condition2BgColor -NoNewline
        Write-Host " Condition 2: DKIM=pass AND header.d matches smtp.mailfrom" -ForegroundColor White

        if ($authResults.Condition2Met) {
            Write-Host "      [PASS] DKIM Result: $($authResults.DKIMResult)" -ForegroundColor Green
            Write-Host "      [PASS] header.d ($($authResults.HeaderD)) = smtp.mailfrom ($($authResults.SMTPMailFrom))" -ForegroundColor Green
        } else {
            Write-Host "      [FAIL] DKIM Result: $($authResults.DKIMResult)" -ForegroundColor Red
            if ($authResults.HeaderD -and $authResults.SMTPMailFrom) {
                if ($authResults.HeaderD.ToLower() -eq $authResults.SMTPMailFrom.ToLower()) {
                    Write-Host "      [PASS] header.d ($($authResults.HeaderD)) = smtp.mailfrom ($($authResults.SMTPMailFrom))" -ForegroundColor Green
                } else {
                    Write-Host "      [FAIL] header.d ($($authResults.HeaderD)) != smtp.mailfrom ($($authResults.SMTPMailFrom))" -ForegroundColor Red
                }
            } else {
                Write-Host "      [FAIL] Missing domain values" -ForegroundColor Red
            }
        }
        Write-Host ""

        # Final result with enhanced highlighting
        $finalResultText = if ($authResults.DMARCPass -eq 'Yes') {
            if ($authResults.Condition1Met -and $authResults.Condition2Met) {
                "PASS - BOTH conditions met (Excellent!)"
            } else {
                "PASS - At least one condition met"
            }
        } else {
            "FAIL - No conditions met"
        }

        Write-Host "  Final Result: $finalResultText" -ForegroundColor $(if ($authResults.DMARCPass -eq 'Yes') { 'Green' }else { 'Red' }) -BackgroundColor $(if ($authResults.DMARCPass -eq 'Yes') { 'DarkGreen' }else { 'DarkRed' })
        Write-Host ""

        # Show detailed analysis
        Write-Host "Detailed Analysis:" -ForegroundColor Gray
        foreach ($detail in $authResults.Details) {
            Write-Host "  $detail" -ForegroundColor DarkGray
        }
        Write-Host ""

        # Show parsed Antispam headers if available
        if ($authResults.AntispamMailboxDelivery) {
            Write-Host "=== X-Microsoft-Antispam-Mailbox-Delivery PARSED ===" -ForegroundColor Magenta
            Write-Host "UCF (Unified Content Filter): $($authResults.AntispamUCF)" -ForegroundColor Cyan
            Write-Host "JMR (Junk Mail Rule): $($authResults.AntispamJMR)" -ForegroundColor Cyan
            Write-Host "Dest (Destination): $($authResults.AntispamDest)" -ForegroundColor Cyan
            Write-Host "OFR (Organizational Filtering Rules): $($authResults.AntispamOFR)" -ForegroundColor Cyan
            Write-Host ""
        }

        if ($authResults.Office365FilteringCorrelationId) {
            Write-Host "=== X-MS-Office365-Filtering-Correlation-Id PARSED ===" -ForegroundColor Magenta
            Write-Host "Correlation ID: $($authResults.Office365FilteringCorrelationId)" -ForegroundColor Cyan
            Write-Host ""
        }

        if ($authResults.ForefrontAntispamReport) {
            Write-Host "=== X-Forefront-Antispam-Report-Untrusted PARSED ===" -ForegroundColor Magenta
            Write-Host "CIP (Client IP): $($authResults.ForefrontCIP)" -ForegroundColor Yellow
            Write-Host "CTRY (Country): $($authResults.ForefrontCTRY)" -ForegroundColor Yellow
            Write-Host "LANG (Language): $($authResults.ForefrontLANG)" -ForegroundColor Yellow
            Write-Host "SCL (Spam Confidence Level): $($authResults.ForefrontSCL)" -ForegroundColor Yellow
            Write-Host "SRV (Service): $($authResults.ForefrontSRV)" -ForegroundColor Yellow
            Write-Host "IPV (IP Version): $($authResults.ForefrontIPV)" -ForegroundColor Yellow
            Write-Host "SFV (Sender Filter Verdict): $($authResults.ForefrontSFV)" -ForegroundColor Yellow
            Write-Host "PTR (Reverse DNS): $($authResults.ForefrontPTR)" -ForegroundColor Yellow
            Write-Host "CAT (Category): $($authResults.ForefrontCAT)" -ForegroundColor Yellow
            Write-Host "DIR (Direction): $($authResults.ForefrontDIR)" -ForegroundColor Yellow
            Write-Host "SFP (Sender Filter Policy): $($authResults.ForefrontSFP)" -ForegroundColor Yellow
            Write-Host ""
        }

        # Now search for domains as before
        Write-Host "=== DOMAIN EXTRACTION ===" -ForegroundColor Yellow
        Write-Host "Searching for smtp.mailfrom and header.from entries..." -ForegroundColor Gray
        Write-Host ""

        # Look for smtp.mailfrom patterns in the entire content
        $smtpMatches = [regex]::Matches($headerContent, 'smtp\.mailfrom=([^;\s\r\n]+)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

        Write-Host "Found $($smtpMatches.Count) smtp.mailfrom matches" -ForegroundColor Gray

        foreach ($match in $smtpMatches) {
            $domain = $match.Groups[1].Value.Trim()
            Write-Host "  Found smtp.mailfrom: '$domain'" -ForegroundColor Cyan

            # Clean up the domain (remove quotes, brackets, etc.)
            $domain = $domain -replace '^["\''<\[\(]', '' -replace '["\''>\]\);,]$', ''
            Write-Host "    Cleaned domain: '$domain'" -ForegroundColor Gray

            # Validate domain format
            if ($domain -match '^[a-zA-Z0-9][a-zA-Z0-9\.-]*[a-zA-Z0-9]\.[a-zA-Z]{2,}$') {
                $domains += $domain
                $foundEntries += "smtp.mailfrom=$domain"
                Write-Host "    + Valid smtp.mailfrom domain: $domain" -ForegroundColor Green
            } else {
                Write-Host "    - Invalid domain format: '$domain'" -ForegroundColor Yellow
            }
        }

        # Look for header.from patterns in the entire content
        $headerFromMatches = [regex]::Matches($headerContent, 'header\.from=([^;\s\r\n]+)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

        Write-Host "Found $($headerFromMatches.Count) header.from matches" -ForegroundColor Gray

        foreach ($match in $headerFromMatches) {
            $domain = $match.Groups[1].Value.Trim()
            Write-Host "  Found header.from: '$domain'" -ForegroundColor Cyan

            # Clean up the domain (remove quotes, brackets, etc.)
            $domain = $domain -replace '^["\''<\[\(]', '' -replace '["\''>\]\);,]$', ''
            Write-Host "    Cleaned domain: '$domain'" -ForegroundColor Gray

            # Validate domain format
            if ($domain -match '^[a-zA-Z0-9][a-zA-Z0-9\.-]*[a-zA-Z0-9]\.[a-zA-Z]{2,}$') {
                $domains += $domain
                $foundEntries += "header.from=$domain"
                Write-Host "    + Valid header.from domain: $domain" -ForegroundColor Green
            } else {
                Write-Host "    - Invalid domain format: '$domain'" -ForegroundColor Yellow
            }
        }

        # Also look for alternative patterns that might be present
        # Look for dmarc= patterns to extract header.from domains
        $dmarcMatches = [regex]::Matches($headerContent, 'dmarc=[^;]*header\.from=([^;\s\r\n]+)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

        Write-Host "Found $($dmarcMatches.Count) DMARC header.from matches" -ForegroundColor Gray

        foreach ($match in $dmarcMatches) {
            $domain = $match.Groups[1].Value.Trim()
            Write-Host "  Found DMARC header.from: '$domain'" -ForegroundColor Cyan

            # Clean up the domain
            $domain = $domain -replace '^["\''<\[\(]', '' -replace '["\''>\]\);,]$', ''
            Write-Host "    Cleaned domain: '$domain'" -ForegroundColor Gray

            # Validate domain format
            if ($domain -match '^[a-zA-Z0-9][a-zA-Z0-9\.-]*[a-zA-Z0-9]\.[a-zA-Z]{2,}$') {
                $domains += $domain
                $foundEntries += "header.from=$domain (from DMARC section)"
                Write-Host "    + Valid DMARC header.from domain: $domain" -ForegroundColor Green
            } else {
                Write-Host "    - Invalid domain format: '$domain'" -ForegroundColor Yellow
            }
        }

        Write-Host ""
        Write-Host "Total domains found before deduplication: $($domains.Count)" -ForegroundColor Gray

        # Remove duplicates while preserving order
        $uniqueDomains = @()
        $seenDomains = @{}

        foreach ($domain in $domains) {
            $domainLower = $domain.ToLower()
            if (-not $seenDomains.ContainsKey($domainLower)) {
                $uniqueDomains += $domain
                $seenDomains[$domainLower] = $true
            }
        }

        Write-Host ""
        if ($uniqueDomains.Count -gt 0) {
            Write-Host "SUCCESS: Found $($uniqueDomains.Count) unique domain(s) for analysis:" -ForegroundColor Green
            foreach ($domain in $uniqueDomains) {
                Write-Host "  - $domain" -ForegroundColor White
            }
            Write-Host ""
            Write-Host "Extracted from $($foundEntries.Count) header entries:" -ForegroundColor Gray
            foreach ($entry in $foundEntries) {
                Write-Host "  - $entry" -ForegroundColor DarkGray
            }
        } else {
            Write-Host "No valid domains found in email headers." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Troubleshooting:" -ForegroundColor Cyan
            Write-Host "The script searches for these patterns in the email headers:" -ForegroundColor White
            Write-Host "  1. smtp.mailfrom=domain.com" -ForegroundColor Gray
            Write-Host "  2. header.from=domain.com" -ForegroundColor Gray
            Write-Host "  3. dmarc=... header.from=domain.com" -ForegroundColor Gray
            Write-Host ""
            Write-Host "Example of expected email header format:" -ForegroundColor Cyan
            Write-Host "Authentication-Results: spf=fail (sender IP is 1.2.3.4)" -ForegroundColor DarkGray
            Write-Host " smtp.mailfrom=example.com; dkim=none (message not signed)" -ForegroundColor DarkGray
            Write-Host " header.d=none;dmarc=fail action=none header.from=example.com" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "If your file has a different format, please check the content." -ForegroundColor White

            # Show first 500 characters of the file for debugging
            if ($headerContent.Length -gt 0) {
                $preview = if ($headerContent.Length -gt 500) {
                    $headerContent.Substring(0, 500) + "..."
                } else {
                    $headerContent
                }
                Write-Host ""
                Write-Host "File content preview (first 500 chars):" -ForegroundColor Yellow
                Write-Host $preview -ForegroundColor DarkGray
            }
        }

        Write-Host ""
        return $uniqueDomains
    } catch {
        Write-Host "Error reading email header file: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# Function to calculate check percentages for donut charts
function Get-ProtocolCheckPercentage {
    param(
        [PSCustomObject]$result,
        [string]$protocol
    )

    switch ($protocol) {
        "SPF" {
            if (-not $result.SPFFound) { return 0 }

            # Calculate SPF score based on new point system
            # Record Present = 8 points, other 8 checks = 4 points each (Total: 40 points)
            $maxPoints = 40
            $earnedPoints = 0

            $spfChecks = Get-ProtocolCheckDetails $result "SPF"
            foreach ($check in $spfChecks) {
                if ($check.Passed) {
                    if ($check.Name -eq "Record Present") {
                        $earnedPoints += 8  # Record present check gets 8 points
                    } else {
                        $earnedPoints += 4  # All other SPF checks get 4 points each
                    }
                }
            }

            return [math]::Round(($earnedPoints / $maxPoints) * 100, 0)
        }

        "DMARC" {
            if (-not $result.DMARCFound) { return 0 }

            # Calculate DMARC score based on new point system
            # Each of the 5 DMARC checks = 6 points each (Total: 30 points)
            $maxPoints = 30
            $earnedPoints = 0

            $dmarcChecks = Get-ProtocolCheckDetails $result "DMARC"
            foreach ($check in $dmarcChecks) {
                if ($check.Passed) {
                    $earnedPoints += 6  # Each DMARC check gets 6 points
                }
            }

            return [math]::Round(($earnedPoints / $maxPoints) * 100, 0)
        }

        "DKIM" {
            if (-not $result.DKIMFound) { return 0 }

            # Calculate DKIM score based on new point system
            # Each of the 5 DKIM checks = 6 points each (Total: 30 points)
            $maxPoints = 30
            $earnedPoints = 0

            $dkimChecks = Get-ProtocolCheckDetails $result "DKIM"
            foreach ($check in $dkimChecks) {
                if ($check.Passed) {
                    $earnedPoints += 6  # Each DKIM check gets 6 points
                }
            }

            return [math]::Round(($earnedPoints / $maxPoints) * 100, 0)
        }
    }

    return 0
}

# Function to generate enhanced interactive segmented donut chart SVG
function Add-SegmentedDonutChart {
    param($checks, $protocol)

    $totalChecks = $checks.Count
    $passedChecks = ($checks | Where-Object { $_.Passed }).Count
    $percentage = if ($totalChecks -gt 0) { [math]::Round(($passedChecks / $totalChecks) * 100, 0) } else { 0 }

    $circumference = 2 * [math]::PI * 15.915
    $segmentSize = $circumference / $totalChecks

    # Generate unique chart ID for interactivity
    $chartId = "chart-$protocol-$(Get-Random)"

    $svg = @"
<svg viewBox="0 0 42 42" class="interactive-donut" id="$chartId">
    <defs>
        <filter id="glow-$protocol" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="2" result="coloredBlur"/>
            <feMerge>
                <feMergeNode in="coloredBlur"/>
                <feMergeNode in="SourceGraphic"/>
            </feMerge>
        </filter>
        <linearGradient id="grad-$protocol" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" style="stop-color:$(if($protocol -eq 'SPF'){'#28a745'}elseif($protocol -eq 'DMARC'){'#007bff'}else{'#b007ff'});stop-opacity:1" />
            <stop offset="100%" style="stop-color:$(if($protocol -eq 'SPF'){'#20c997'}elseif($protocol -eq 'DMARC'){'#6610f2'}else{'#e83e8c'});stop-opacity:1" />
        </linearGradient>
    </defs>
    <circle class="background" cx="21" cy="21" r="15.915" fill="none" stroke="#e9ecef" stroke-width="4"></circle>
"@

    $currentOffset = 0
    for ($i = 0; $i -lt $checks.Count; $i++) {
        $check = $checks[$i]
        $segmentId = "$chartId-segment-$i"
        $segmentColor = if ($check.Passed) { $check.Color } else { "#dee2e6" }
        $segmentOpacity = if ($check.Passed) { "1.0" } else { "0.6" }

        $svg += @"
    <circle id="$segmentId" cx="21" cy="21" r="15.915" fill="none"
        stroke="$segmentColor"
        stroke-width="4"
        stroke-dasharray="$segmentSize $($circumference - $segmentSize)"
        stroke-dashoffset="$currentOffset"
        stroke-linecap="round"
        opacity="$segmentOpacity"
        class="chart-segment $(if($check.Passed){'passed-segment'}else{'failed-segment'})"
        data-check="$($check.Name)"
        data-status="$(if($check.Passed){'PASS'}else{'FAIL'})"
        data-protocol="$protocol"
        onmouseover="highlightSegment('$segmentId', '$($check.Name)', '$(if($check.Passed){'PASS'}else{'FAIL'})', '$protocol')"
        onmouseout="resetSegment('$segmentId')"
        style="cursor: pointer; transition: all 0.3s ease;">
    </circle>
"@
        $currentOffset -= $segmentSize
    }

    $svg += @"
</svg>
<div class="percentage-display">
    <div class="percentage-number">$percentage%</div>
    <div class="percentage-label">Compliant</div>
</div>
"@

    return $svg
}

# Function to get individual check results for segmented charts
function Get-ProtocolCheckDetails {
    param($result, $protocol)

    $checks = @()

    switch ($protocol) {
        "SPF" {
            $checks += @{
                Name   = "Record Present"
                Passed = $result.SPFFound
                Color  = if ($result.SPFFound) { "#28a745" } else { "#dc3545" }
            }
            $checks += @{
                Name   = "Single Record"
                Passed = ($result.SPFFound -and $result.SPFMultipleRecordsCheck)
                Color  = if ($result.SPFFound -and $result.SPFMultipleRecordsCheck) { "#28a745" } else { "#dc3545" }
            }
            $checks += @{
                Name   = "Macro Security"
                Passed = ($result.SPFFound -and $result.SPFMacroSecurityCheck)
                Color  = if ($result.SPFFound -and $result.SPFMacroSecurityCheck) { "#28a745" } else { "#dc3545" }
            }
            $checks += @{
                Name   = "TTL Sub-Records"
                Passed = ($result.SPFFound -and $result.SPFSubRecordsTTLCheck)
                Color  = if ($result.SPFFound -and $result.SPFSubRecordsTTLCheck) { "#28a745" } else { "#dc3545" }
            }
            $checks += @{
                Name   = "DNS Lookups < 10"
                Passed = ($result.SPFFound -and $result.SpfDnsLookups -le 10)
                Color  = if ($result.SPFFound -and $result.SpfDnsLookups -le 10) { "#28a745" } else { "#dc3545" }
            }
            $checks += @{
                Name   = "Record Length < 255"
                Passed = ($result.SPFFound -and $result.SPFRecordLength -le 255)
                Color  = if ($result.SPFFound -and $result.SPFRecordLength -le 255) { "#28a745" } else { "#dc3545" }
            }
            $checks += @{
                Name   = "TTL >= 3600"
                Passed = ($result.SPFFound -and $result.SpfTTL -ge 3600)
                Color  = if ($result.SPFFound -and $result.SpfTTL -ge 3600) { "#28a745" } else { "#dc3545" }
            }
            $checks += @{
                Name   = "Strict All Mechanism"
                Passed = ($result.SPFFound -and ($result.SPFAllMechanism -eq "~all" -or $result.SPFAllMechanism -eq "-all"))
                Color  = if ($result.SPFFound -and ($result.SPFAllMechanism -eq "~all" -or $result.SPFAllMechanism -eq "-all")) { "#28a745" } else { "#dc3545" }
            }
            $checks += @{
                Name   = "Syntax Valid"
                Passed = ($result.SPFFound -and $result.SPFSyntaxValid)
                Color  = if ($result.SPFFound -and $result.SPFSyntaxValid) { "#28a745" } else { "#dc3545" }
            }
        }

        "DMARC" {
            $checks += @{
                Name   = "Record Present"
                Passed = $result.DMARCFound
                Color  = if ($result.DMARCFound) { "#007bff" } else { "#dc3545" }
            }
            $checks += @{
                Name   = "Reporting Configured"
                Passed = ($result.DMARCFound -and $result.DMARCRecord -match "rua=")
                Color  = if ($result.DMARCFound -and $result.DMARCRecord -match "rua=") { "#007bff" } else { "#dc3545" }
            }
            $checks += @{
                Name   = "Strong Policy (reject only)"
                Passed = ($result.DMARCFound -and $result.DMARCPolicy -eq "reject")
                Color  = if ($result.DMARCFound -and $result.DMARCPolicy -eq "reject") { "#007bff" } else { "#dc3545" }
            }
            $checks += @{
                Name   = "Subdomain Policy"
                Passed = ($result.DMARCFound -and $result.DMARCSubdomainPolicy -ne "Missing" -and ($result.DMARCSubdomainPolicy -eq $result.DMARCPolicy -or $result.DMARCSubdomainPolicy -eq "quarantine" -or $result.DMARCSubdomainPolicy -eq "reject"))
                Color  = if ($result.DMARCFound -and $result.DMARCSubdomainPolicy -ne "Missing" -and ($result.DMARCSubdomainPolicy -eq $result.DMARCPolicy -or $result.DMARCSubdomainPolicy -eq "quarantine" -or $result.DMARCSubdomainPolicy -eq "reject")) { "#007bff" } else { "#dc3545" }
            }
            $checks += @{
                Name   = "TTL >= 3600"
                Passed = ($result.DMARCFound -and $result.DmarcTTL -ge 3600)
                Color  = if ($result.DMARCFound -and $result.DmarcTTL -ge 3600) { "#007bff" } else { "#dc3545" }
            }
        }

        "DKIM" {
            $checks += @{
                Name   = "Record Present"
                Passed = $result.DKIMFound
                Color  = if ($result.DKIMFound) { "#b007ff" } else { "#dc3545" }
            }
            $checks += @{
                Name   = "Syntax Valid"
                Passed = ($result.DKIMFound -and $result.DKIMSyntaxValid)
                Color  = if ($result.DKIMFound -and $result.DKIMSyntaxValid) { "#b007ff" } else { "#dc3545" }
            }

            $activeKeys = 0
            foreach ($status in $result.DKIMAllMechanisms.Values) {
                if ($status -eq "ACTIVE") { $activeKeys++ }
            }
            $checks += @{
                Name   = "Keys Active"
                Passed = ($result.DKIMFound -and $activeKeys -gt 0)
                Color  = if ($result.DKIMFound -and $activeKeys -gt 0) { "#b007ff" } else { "#dc3545" }
            }

            $hasWeakKeys = $false
            foreach ($keyInfo in $result.DKIMKeyLengths.Values) {
                if ($keyInfo.IsWeak) { $hasWeakKeys = $true; break }
            }
            $checks += @{
                Name   = "Strong Keys"
                Passed = ($result.DKIMFound -and -not $hasWeakKeys)
                Color  = if ($result.DKIMFound -and -not $hasWeakKeys) { "#b007ff" } else { "#dc3545" }
            }

            # Check TTL for all DKIM selectors
            $allTTLValid = $true
            if ($result.DKIMFound) {
                foreach ($selector in $result.DKIMSelectors) {
                    if ($result.DkimTTL.ContainsKey($selector)) {
                        if ($result.DkimTTL[$selector] -lt 3600) {
                            $allTTLValid = $false
                            break
                        }
                    }
                }
            } else {
                $allTTLValid = $false
            }
            $checks += @{
                Name   = "TTL >= 3600"
                Passed = ($result.DKIMFound -and $allTTLValid)
                Color  = if ($result.DKIMFound -and $allTTLValid) { "#b007ff" } else { "#dc3545" }
            }
        }
    }

    return $checks
}

# Function to get explanation for authentication reason codes
function Get-ReasonCodeExplanation {
    param(
        [string]$ReasonCode
    )

    if (-not $ReasonCode -or $ReasonCode -eq "") {
        return ""
    }

    # Handle different reason code patterns
    $explanations = @{
        "000" = "The message failed explicit authentication (compauth=fail). For example, the message received a DMARC fail and the DMARC policy action is p=quarantine or p=reject."
        "001" = "The message failed implicit authentication (compauth=fail). This result means that the sending domain didn't have email authentication records published, or if they did, they had a weaker failure policy (SPF ~all or ?all, or a DMARC policy of p=none)."
        "002" = "The organization has a policy for the sender/domain pair that is explicitly prohibited from sending spoofed email. An admin manually configures this setting."
        "010" = "The message failed DMARC, the DMARC policy action is p=reject or p=quarantine, and the sending domain is one of your organization's accepted domains (self-to-self or intra-org spoofing)."
    }

    # Check for exact matches first
    if ($explanations.ContainsKey($ReasonCode)) {
        return $explanations[$ReasonCode]
    }

    # Check for pattern matches
    if ($ReasonCode -match "^1\d{2}$" -or $ReasonCode -match "^7\d{2}$") {
        if ($ReasonCode -eq "130") {
            return "The message passed authentication (compauth=pass). The ARC result was used to override a DMARC failure."
        } else {
            return "The message passed authentication (compauth=pass). The last two digits are internal codes used by Microsoft 365."
        }
    } elseif ($ReasonCode -match "^2\d{2}$") {
        return "The message soft-passed implicit authentication (compauth=softpass). The last two digits are internal codes used by Microsoft 365."
    } elseif ($ReasonCode -match "^3\d{2}$") {
        return "The message wasn't checked for composite authentication (compauth=none)."
    } elseif ($ReasonCode -match "^4\d{2}$" -or $ReasonCode -match "^9\d{2}$") {
        return "The message bypassed composite authentication (compauth=none). The last two digits are internal codes used by Microsoft 365."
    } elseif ($ReasonCode -match "^6\d{2}$") {
        return "The message failed implicit email authentication, and the sending domain is one of your organization's accepted domains (self-to-self or intra-org spoofing)."
    }

    # Return empty string if no pattern matches
    return ""
}

. $PSScriptRoot\..\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1

$BuildVersion = ""

Write-Host ("EmailAuthenticationChecker.ps1 script version $($BuildVersion)") -ForegroundColor Green

if ($ScriptUpdateOnly) {
    switch (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/EmailAuthenticationChecker-VersionsURL" -Confirm:$false) {
        ($true) { Write-Host ("Script was successfully updated.") -ForegroundColor Green }
        ($false) { Write-Host ("No update of the script performed.") -ForegroundColor Yellow }
        default { Write-Host ("Unable to perform ScriptUpdateOnly operation.") -ForegroundColor Red }
    }
    return
}

if ((-not($SkipVersionCheck)) -and (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/EmailAuthenticationChecker-VersionsURL" -Confirm:$false)) {
    Write-Host ("Script was updated. Please re-run the command.") -ForegroundColor Yellow
    return
}

# Results storage
$allResults = @()

# Determine input method based on parameters or show interactive menu
if ($Domain) {
    # Single domain analysis via parameter
    if (-not (Test-DomainFormat -DomainName $Domain -Context "single")) {
        exit 1
    }
    $domains = @($Domain.Trim())
    # Set menu choice to indicate single domain analysis mode
    $menuChoice = '1'
} elseif ($DomainList) {
    # Multiple domain analysis via parameter
    if (-not (Test-DomainFormat -DomainName $DomainList -Context "multiple")) {
        exit 1
    }
    $domains = $DomainList -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    # Set menu choice to indicate multiple domain analysis mode
    $menuChoice = '2'
} elseif ($FilePath) {
    # File-based analysis via parameter
    if (-not (Test-Path -Path $FilePath)) {
        Write-Host "File not found: $FilePath" -ForegroundColor Red
        exit 1
    }
    try {
        $domains = Get-Content -Path $FilePath | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() }
        if ($domains.Count -eq 0) {
            Write-Host "No domains found in file: $FilePath" -ForegroundColor Red
            exit 1
        }
        Write-Host "Loaded $($domains.Count) domains from file." -ForegroundColor Green
    } catch {
        Write-Host "Error reading file: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
    # Set menu choice to indicate file-based analysis mode
    $menuChoice = '3'
} elseif ($HeaderFilePath) {
    # Header-based analysis via parameter
    if (-not (Test-Path -Path $HeaderFilePath)) {
        Write-Host "Header file not found: $HeaderFilePath" -ForegroundColor Red
        exit 1
    }
    try {
        $domains = Get-DomainsFromEmailHeaders -FilePath $HeaderFilePath
        if ($domains -and $domains.Count -gt 0) {
            Write-Host "Extracted domains from headers: $($domains -join ', ')" -ForegroundColor Green
        } else {
            Write-Host "No valid domains found in header file." -ForegroundColor Red
            exit 1
        }
    } catch {
        Write-Host "Error reading header file: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
    # Set menu choice to indicate header analysis mode
    $menuChoice = '4'
} else {
    # No parameters provided - show usage and exit
    Write-Host "Email Authentication Checker v1.5" -ForegroundColor Cyan
    Write-Host "Please provide parameters to run the script:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor White
    Write-Host "  Single domain:     .\EmailAuthChecker.ps1 -Domain 'microsoft.com'" -ForegroundColor Gray
    Write-Host "  Multiple domains:  .\EmailAuthChecker.ps1 -DomainList 'microsoft.com,contoso.com'" -ForegroundColor Gray
    Write-Host "  From file:         .\EmailAuthChecker.ps1 -FilePath 'domains.txt'" -ForegroundColor Gray
    Write-Host "  From headers:      .\EmailAuthChecker.ps1 -HeaderFilePath 'headers.txt'" -ForegroundColor Gray
    Write-Host "  With custom output: .\EmailAuthChecker.ps1 -Domain 'microsoft.com' -OutputPath 'C:\Reports' -AutoOpen" -ForegroundColor Gray
    Write-Host ""
    Write-Host "For help: Get-Help .\EmailAuthChecker.ps1 -Full" -ForegroundColor White
    exit 1
}

# Common DKIM selectors to check - expanded list for better detection
$commonSelectors = @("default", "selector1", "selector2", "Google", "Gmail", "k1", "k2", "dkim", "mail", "email", "s1", "s2", "smtpapi", "AmazonSES", "Mandrill", "Mailgun", "pm", "Zendesk1", "mxvault")

foreach ($domain in $domains) {
    Write-Host "Analyzing domain: $domain" -ForegroundColor Yellow
    Write-Host "- * 50" -ForegroundColor DarkGray

    # Get authoritative servers for this domain
    $authServers = Get-AuthoritativeDNSServers $domain
    if ($authServers.Count -gt 0) {
        Write-Host "    Authoritative DNS servers found:" -ForegroundColor Gray
        foreach ($server in $authServers) {
            Write-Host "      - $($server.NameHost) ($($server.IPAddress))" -ForegroundColor Gray
        }
    } else {
        Write-Host "    No authoritative DNS servers found, using default resolvers" -ForegroundColor Yellow
    }
    Write-Host ""

    # Initialize result object
    $result = [PSCustomObject]@{
        Domain                                     = $domain
        SPFFound                                   = $false
        SPFRecord                                  = ""
        SPFIssues                                  = @()
        SpfDnsLookups                              = 0
        SPFRecordLength                            = 0
        SpfTTL                                     = 0
        SPFAllMechanism                            = ""
        SPFSyntaxValid                             = $true
        SPFSyntaxIssues                            = @()
        DMARCFound                                 = $false
        DMARCRecord                                = ""
        DMARCPolicy                                = ""
        DMARCSubdomainPolicy                       = ""  # sp= tag
        DmarcSPFAlignment                          = ""     # aspf= tag
        DmarcDKIMAlignment                         = ""    # adkim= tag
        DMARCFailureOptions                        = ""   # fo= tag (failure reporting options)
        DMARCVersion                               = ""          # v= tag
        DMARCPercentage                            = ""       # pct= tag
        DmarcTTL                                   = 0
        DMARCIssues                                = @()
        DKIMFound                                  = $false
        DKIMSelectors                              = @()
        DKIMRecords                                = @{}  # Dictionary to store selector -> record mapping
        DKIMAllMechanisms                          = @{}  # Dictionary to store selector -> all mechanism mapping
        DKIMKeyLengths                             = @{}  # Dictionary to store selector -> key length info mapping
        DkimTTL                                    = @{}  # Dictionary to store selector -> TTL mapping
        DkimTTLIssues                              = @{}  # Dictionary to store selector -> TTL issues mapping
        DKIMSyntaxValid                            = $true
        DKIMSyntaxIssues                           = @{}  # Dictionary to store selector -> issues mapping
        SPFMultipleRecordsCheck                    = $true  # New check for multiple SPF records
        SPFMacroSecurityCheck                      = $true  # New check for SPF macro security
        SPFSubRecordsTTLCheck                      = $true  # New check for TTL of sub-records (A/MX/TXT records referenced in SPF)
        SPFSubRecordsTTLValues                     = @{}  # Dictionary to store domain -> TTL values for A/MX/TXT records referenced in SPF
        # MX Record Analysis Results
        MXFound                                    = $false
        MXRecords                                  = @()
        MXMinTTL                                   = 0
        MXMaxTTL                                   = 0
        MXAverageTTL                               = 0
        MXProviders                                = @()
        MXPrimaryMX                                = ""
        MXBackupMX                                 = @()
        # Email Header Analysis Results (for option 4)
        EmailHeaderSPFResult                       = ""
        EmailHeaderDKIMResult                      = ""
        EmailHeaderDMARCResult                     = ""
        EmailHeaderAction                          = ""
        EmailHeaderSMTPMailFrom                    = ""
        EmailHeaderHeaderFrom                      = ""
        EmailHeaderHeaderD                         = ""
        EmailHeaderCompAuth                        = ""
        EmailHeaderReason                          = ""
        EmailHeaderAuthenticationResultsRaw        = ""
        EmailHeaderDMARCPass                       = ""
        EmailHeaderCondition1Met                   = $false
        EmailHeaderCondition2Met                   = $false
        EmailHeaderAntispamMailboxDelivery         = ""
        EmailHeaderAntispamUCF                     = ""
        EmailHeaderAntispamJMR                     = ""
        EmailHeaderAntispamDest                    = ""
        EmailHeaderAntispamOFR                     = ""
        EmailHeaderOffice365FilteringCorrelationId = ""
        EmailHeaderForefrontAntispamReport         = ""
        EmailHeaderForefrontCIP                    = ""
        EmailHeaderForefrontCTRY                   = ""
        EmailHeaderForefrontLANG                   = ""
        EmailHeaderForefrontSCL                    = ""
        EmailHeaderForefrontSRV                    = ""
        EmailHeaderForefrontIPV                    = ""
        EmailHeaderForefrontSFV                    = ""
        EmailHeaderForefrontPTR                    = ""
        EmailHeaderForefrontCAT                    = ""
        EmailHeaderForefrontDIR                    = ""
        EmailHeaderForefrontSFP                    = ""
        Score                                      = 0
        Status                                     = ""
        Recommendations                            = @()
    }

    # CHECK SPF RECORD
    Write-Host "  [1/4] Checking SPF record..." -ForegroundColor White

    # First, check for multiple SPF records (RFC violation)
    $multipleSPFIssues = Test-MultipleSPFRecords $domain
    if ($multipleSPFIssues.Count -gt 0) {
        $result.SPFMultipleRecordsCheck = $false
        foreach ($issue in $multipleSPFIssues) {
            $result.SPFIssues += $issue
        }
        Write-Host "        Multiple SPF records detected - RFC violation!" -ForegroundColor Red
        foreach ($issue in $multipleSPFIssues) {
            if ($issue -like "SPF Record*") {
                Write-Host "        $issue" -ForegroundColor Yellow
            }
        }
    } else {
        $result.SPFMultipleRecordsCheck = $true
        Write-Host "        Single SPF record compliance: PASSED" -ForegroundColor Green
    }

    # Query SPF record from authoritative servers
    $authServers = Get-AuthoritativeDNSServers $domain
    $spfTxtRecords = Resolve-DnsNameAuthoritative -Name $domain -Type TXT -AuthoritativeServers $authServers
    $spfRecord = $spfTxtRecords | Where-Object { $_.Strings -like "v=spf*" } | Select-Object -First 1

    if ($spfRecord) {
        $result.SPFFound = $true
        $result.SPFRecord = $spfRecord.Strings -join ""
        $result.SpfTTL = $spfRecord.TTL
        Write-Host "        SPF record found" -ForegroundColor Green

        # Extract and analyze SPF all mechanism
        $allMechanism = Get-SPFAllMechanism $result.SPFRecord
        $result.SPFAllMechanism = $allMechanism

        # Check SPF all mechanism issues with detailed analysis
        if ($allMechanism -eq "+all") {
            $result.SPFIssues += "Uses '+all' (allows any server) - CRITICAL SECURITY RISK"
            Write-Host "        All Mechanism: +all (CRITICAL - allows any server)" -ForegroundColor Red
        } elseif ($allMechanism -eq "?all") {
            $result.SPFIssues += "Uses '?all' (neutral/weak protection) - provides minimal security"
            Write-Host "        All Mechanism: ?all (WEAK - neutral protection)" -ForegroundColor Yellow
        } elseif ($allMechanism -eq "~all") {
            Write-Host "        All Mechanism: ~all (GOOD - soft fail recommended)" -ForegroundColor Green
        } elseif ($allMechanism -eq "-all") {
            Write-Host "        All Mechanism: -all (STRICT - hard fail)" -ForegroundColor Green
        } elseif ([string]::IsNullOrEmpty($allMechanism)) {
            $result.SPFIssues += "Missing 'all' mechanism - SPF policy incomplete"
            Write-Host "        All Mechanism: MISSING (policy incomplete)" -ForegroundColor Red
        } else {
            $result.SPFIssues += "Unknown 'all' mechanism format: $allMechanism"
            Write-Host "        All Mechanism: $allMechanism (UNKNOWN format)" -ForegroundColor Yellow
        }

        # Check SPF record length (RFC 7208 - DNS TXT record limit is 255 characters)
        $result.SPFRecordLength = $result.SPFRecord.Length
        if ($result.SPFRecordLength -gt 255) {
            $result.SPFIssues += "Record too long ($($result.SPFRecordLength) characters) - exceeds 255 character limit"
            Write-Host "        Record Length: $($result.SPFRecordLength) characters (EXCEEDS LIMIT)" -ForegroundColor Red
        } elseif ($result.SPFRecordLength -gt 200) {
            $result.SPFIssues += "Record approaching length limit ($($result.SPFRecordLength) characters) - consider optimization"
            Write-Host "        Record Length: $($result.SPFRecordLength) characters (approaching limit)" -ForegroundColor Yellow
        } else {
            Write-Host "        Record Length: $($result.SPFRecordLength) characters" -ForegroundColor Green
        }

        # Count DNS lookups in SPF record
        $dnsLookupCount = Get-SpfDnsLookupCount $result.SPFRecord
        $result.SpfDnsLookups = $dnsLookupCount

        if ($dnsLookupCount -gt 10) {
            $result.SPFIssues += "Exceeds DNS lookup limit ($dnsLookupCount/10 lookups) - SPF will fail"
        } elseif ($dnsLookupCount -gt 8) {
            $result.SPFIssues += "Near DNS lookup limit ($dnsLookupCount/10 lookups) - consider optimization"
        } else {
            Write-Host "        DNS lookups: $dnsLookupCount/10" -ForegroundColor Green
        }

        # Check TTL (Time To Live) - recommend minimum 3600 seconds (1 hour)
        if ($result.SpfTTL -lt 3600) {
            $result.SPFIssues += "Low TTL for domain $domain ($($result.SpfTTL) seconds) - recommend minimum 3600 seconds for stability"
            Write-Host "        TTL warning: $($result.SpfTTL) seconds (recommend 3600+)" -ForegroundColor Yellow
        } else {
            Write-Host "        TTL: $($result.SpfTTL) seconds" -ForegroundColor Green
        }

        # Validate SPF syntax
        $syntaxIssues = Test-SPFSyntax $result.SPFRecord
        $result.SPFSyntaxIssues = $syntaxIssues
        $result.SPFSyntaxValid = ($syntaxIssues.Count -eq 0)

        if ($syntaxIssues.Count -gt 0) {
            Write-Host "        Syntax issues found: $($syntaxIssues.Count)" -ForegroundColor Yellow
            # Add syntax issues to general SPF issues for scoring
            foreach ($syntaxIssue in $syntaxIssues) {
                $result.SPFIssues += "Syntax: $syntaxIssue"
            }
        } else {
            Write-Host "        Syntax validation: PASSED" -ForegroundColor Green
        }

        # Validate SPF macro security
        $macroSecurityIssues = Test-SPFMacroSecurity $result.SPFRecord
        if ($macroSecurityIssues.Count -gt 0) {
            $result.SPFMacroSecurityCheck = $false
            Write-Host "        Macro security issues found: $($macroSecurityIssues.Count)" -ForegroundColor Yellow
            foreach ($macroIssue in $macroSecurityIssues) {
                $result.SPFIssues += "Macro Security: $macroIssue"
            }
        } else {
            $result.SPFMacroSecurityCheck = $true
            Write-Host "        Macro security validation: PASSED" -ForegroundColor Green
        }

        # Validate TTL for SPF sub-records (A/MX records referenced in SPF)
        $subRecordsTTLIssues = Test-SPFSubRecordsTTL $result.SPFRecord $domain
        $result.SPFSubRecordsTTLValues = Get-SPFSubRecordsTTLValues $result.SPFRecord $domain
        if ($subRecordsTTLIssues.Count -gt 0) {
            $result.SPFSubRecordsTTLCheck = $false
            Write-Host "        TTL sub-records issues found: $($subRecordsTTLIssues.Count)" -ForegroundColor Yellow
            foreach ($ttlIssue in $subRecordsTTLIssues) {
                $result.SPFIssues += "TTL Sub-Records: $ttlIssue"
            }
        } else {
            $result.SPFSubRecordsTTLCheck = $true
            Write-Host "        TTL sub-records validation: PASSED" -ForegroundColor Green
        }

        if ($result.SPFIssues.Count -gt 0) {
            $issuesList = $result.SPFIssues -join '; '
            Write-Host "        Warning: $issuesList" -ForegroundColor Yellow
        }
    } else {
        Write-Host "        No SPF record found" -ForegroundColor Red
        # Set all SPF check flags to false when SPF record is not found
        $result.SPFMultipleRecordsCheck = $false
        $result.SPFMacroSecurityCheck = $false
        $result.SPFSubRecordsTTLCheck = $false
        $result.SPFSyntaxValid = $false
        # Set specific values for missing SPF record
        $result.SPFAllMechanism = "Missing"
        $result.SPFIssues += "SPF record not found - implement SPF protection"
    }

    # CHECK DMARC RECORD
    Write-Host "  [2/4] Checking DMARC record..." -ForegroundColor White
    $dmarcDomain = "_dmarc.$domain"
    # Query DMARC record from authoritative servers
    $dmarcAuthServers = Get-AuthoritativeDNSServers $domain
    $dmarcTxtRecords = Resolve-DnsNameAuthoritative -Name $dmarcDomain -Type TXT -AuthoritativeServers $dmarcAuthServers
    $dmarcRecord = $dmarcTxtRecords | Where-Object { $_.Strings -match "^v=DMARC1" } | Select-Object -First 1

    if ($dmarcRecord) {
        $result.DMARCFound = $true
        $result.DMARCRecord = $dmarcRecord.Strings -join ""
        $result.DmarcTTL = $dmarcRecord.TTL
        Write-Host "        DMARC record found" -ForegroundColor Green

        # Extract main policy (p=)
        if ($result.DMARCRecord -match "p=(\w+)") {
            $result.DMARCPolicy = $matches[1]
            Write-Host "        Policy: $($result.DMARCPolicy)" -ForegroundColor Cyan
        }

        # Extract subdomain policy (sp=)
        if ($result.DMARCRecord -match "sp=(\w+)") {
            $result.DMARCSubdomainPolicy = $matches[1]
            Write-Host "        Subdomain Policy: $($result.DMARCSubdomainPolicy)" -ForegroundColor Cyan
        } else {
            # If sp= is not specified, it defaults to the main policy
            $result.DMARCSubdomainPolicy = $result.DMARCPolicy
            Write-Host "        Subdomain Policy: $($result.DMARCSubdomainPolicy) (inherited from main policy)" -ForegroundColor Gray
        }

        # Extract SPF alignment mode (aspf=)
        if ($result.DMARCRecord -match "aspf=([rs])") {
            $result.DmarcSPFAlignment = $matches[1]
            $alignmentText = if ($matches[1] -eq "r") { "relaxed" } else { "strict" }
            Write-Host "        SPF Alignment: $alignmentText ($($matches[1]))" -ForegroundColor Cyan
        } else {
            # Default is relaxed if not specified
            $result.DmarcSPFAlignment = "r"
            Write-Host "        SPF Alignment: relaxed (r) - default" -ForegroundColor Gray
        }

        # Extract DKIM alignment mode (adkim=)
        if ($result.DMARCRecord -match "adkim=([rs])") {
            $result.DmarcDKIMAlignment = $matches[1]
            $alignmentText = if ($matches[1] -eq "r") { "relaxed" } else { "strict" }
            Write-Host "        DKIM Alignment: $alignmentText ($($matches[1]))" -ForegroundColor Cyan
        } else {
            # Default is relaxed if not specified
            $result.DmarcDKIMAlignment = "r"
            Write-Host "        DKIM Alignment: relaxed (r) - default" -ForegroundColor Gray
        }

        # Extract failure reporting options (fo=)
        if ($result.DMARCRecord -match "fo=([01ds])") {
            $result.DMARCFailureOptions = $matches[1]
            Write-Host "        Failure Options: $($matches[1])" -ForegroundColor Cyan
        } else {
            # Default is 0 if not specified
            $result.DMARCFailureOptions = "0"
            Write-Host "        Failure Options: 0 (default)" -ForegroundColor Gray
        }

        # Extract DMARC version (v=)
        if ($result.DMARCRecord -match "v=([^;]+)") {
            $result.DMARCVersion = $matches[1].Trim()
            Write-Host "        Protocol Version: $($result.DMARCVersion)" -ForegroundColor Cyan
        } else {
            $result.DMARCVersion = "Unknown"
        }

        # Extract percentage of messages subjected to filtering (pct=)
        if ($result.DMARCRecord -match "pct=(\d+)") {
            $result.DMARCPercentage = $matches[1]
            Write-Host "        Percentage of messages filtered: $($result.DMARCPercentage)%" -ForegroundColor Cyan
        } else {
            # Default is 100% if not specified
            $result.DMARCPercentage = "100"
            Write-Host "        Percentage of messages filtered: 100% (default)" -ForegroundColor Gray
        }

        # Check DMARC issues
        if ($result.DMARCPolicy -eq "none") {
            $result.DMARCIssues += "Policy is 'none' (monitoring only)"
        }

        # Validate subdomain policy
        $validPolicies = @("none", "quarantine", "reject")
        if ($result.DMARCSubdomainPolicy -notin $validPolicies) {
            $result.DMARCIssues += "Invalid subdomain policy: '$($result.DMARCSubdomainPolicy)' (valid: $($validPolicies -join ', '))"
        }

        # Check if subdomain policy is weaker than main policy
        $policyStrength = @{ "none" = 0; "quarantine" = 1; "reject" = 2 }
        if ($policyStrength[$result.DMARCSubdomainPolicy] -lt $policyStrength[$result.DMARCPolicy]) {
            $result.DMARCIssues += "Subdomain policy '$($result.DMARCSubdomainPolicy)' is weaker than main policy '$($result.DMARCPolicy)' - consider strengthening"
        }

        # Validate alignment modes
        $validAlignmentModes = @("r", "s")
        if ($result.DmarcSPFAlignment -notin $validAlignmentModes) {
            $result.DMARCIssues += "Invalid SPF alignment mode: '$($result.DmarcSPFAlignment)' (valid: r=relaxed, s=strict)"
        }
        if ($result.DmarcDKIMAlignment -notin $validAlignmentModes) {
            $result.DMARCIssues += "Invalid DKIM alignment mode: '$($result.DmarcDKIMAlignment)' (valid: r=relaxed, s=strict)"
        }

        if ($result.DMARCRecord -notmatch "rua=") {
            $result.DMARCIssues += "No reporting email configured"
        }

        # Check TTL (Time To Live) - recommend minimum 3600 seconds (1 hour)
        if ($result.DmarcTTL -lt 3600) {
            $result.DMARCIssues += "Low TTL for domain $domain ($($result.DmarcTTL) seconds) - recommend minimum 3600 seconds for stability"
            Write-Host "        TTL warning: $($result.DmarcTTL) seconds (recommend 3600+)" -ForegroundColor Yellow
        } else {
            Write-Host "        TTL: $($result.DmarcTTL) seconds" -ForegroundColor Green
        }

        if ($result.DMARCIssues.Count -gt 0) {
            $issuesList = $result.DMARCIssues -join '; '
            Write-Host "        Warning: $issuesList" -ForegroundColor Yellow
        }
    } else {
        Write-Host "        No DMARC record found" -ForegroundColor Red
        # Set default values for missing DMARC record
        $result.DMARCPolicy = "Missing"
        $result.DMARCSubdomainPolicy = "Missing"
        $result.DmarcSPFAlignment = "Missing"
        $result.DmarcDKIMAlignment = "Missing"
        $result.DMARCFailureOptions = "Missing"
        $result.DMARCVersion = "Missing"
        $result.DMARCPercentage = "Missing"
        $result.DmarcTTL = 0
    }
    # CHECK DKIM RECORDS
    Write-Host "  [3/4] Checking DKIM records..." -ForegroundColor White
    # DKIM checking with fallback mechanism for better reliability
    foreach ($selector in $commonSelectors) {
        $dkimDomain = "$selector._domainkey.$domain"
        $dkimRecord = $null

        # Debug output
        Write-Verbose "Checking DKIM selector: $dkimDomain"

        # Try authoritative servers first, then fallback to regular DNS
        try {
            # Query DKIM record from authoritative servers for accurate TTL
            $dkimAuthServers = Get-AuthoritativeDNSServers $domain
            if ($dkimAuthServers.Count -gt 0) {
                Write-Verbose "Using $($dkimAuthServers.Count) authoritative servers for DKIM query"
                $dkimTxtRecords = Resolve-DnsNameAuthoritative -Name $dkimDomain -Type TXT -AuthoritativeServers $dkimAuthServers
                $dkimRecord = $dkimTxtRecords | Where-Object {
                    # More inclusive pattern - any TXT record containing DKIM-related tags
                    ($_.Strings -join '') -match "v=DKIM1|k=|p=|t=|s=|h="
                } | Select-Object -First 1
            }
        } catch {
            Write-Verbose "Authoritative DKIM query failed for $dkimDomain`: $_"
        }

        # Fallback to regular DNS query if authoritative failed
        if (-not $dkimRecord) {
            try {
                Write-Verbose "Falling back to regular DNS query for $dkimDomain"
                $dkimTxtRecords = Resolve-DnsName -Name $dkimDomain -Type TXT -ErrorAction SilentlyContinue
                if ($dkimTxtRecords) {
                    Write-Verbose "Found $($dkimTxtRecords.Count) TXT records for $dkimDomain"
                    foreach ($txtRecord in $dkimTxtRecords) {
                        Write-Verbose "TXT Record: $($txtRecord.Strings -join '')"
                    }
                }
                $dkimRecord = $dkimTxtRecords | Where-Object {
                    # More inclusive pattern - any TXT record containing DKIM-related tags
                    ($_.Strings -join '') -match "v=DKIM1|k=|p=|t=|s=|h="
                } | Select-Object -First 1
            } catch {
                Write-Verbose "Regular DKIM query failed for $dkimDomain`: $_"
            }
        }

        if ($dkimRecord) {
            $result.DKIMFound = $true
            $result.DKIMSelectors += $selector
            $dkimRecordString = $dkimRecord.Strings -join ""
            $result.DKIMRecords[$selector] = $dkimRecordString
            $result.DkimTTL[$selector] = $dkimRecord.TTL

            # Display individual selector details
            Write-Host "        DKIM selector '$selector' found" -ForegroundColor Green
            if ($selector -eq "selector1" -or $selector -eq "selector2") {
                Write-Host "        $selector record: $dkimRecordString" -ForegroundColor Cyan
            }

            # Check TTL (Time To Live) - recommend minimum 3600 seconds (1 hour)
            $ttlIssues = @()
            if ($dkimRecord.TTL -lt 3600) {
                $ttlIssues += "Low TTL ($($dkimRecord.TTL) seconds) - recommend minimum 3600 seconds for stability"
                Write-Host "        $selector TTL warning: $($dkimRecord.TTL) seconds (recommend 3600+)" -ForegroundColor Yellow
            } else {
                Write-Host "        $selector TTL: $($dkimRecord.TTL) seconds" -ForegroundColor Green
            }
            $result.DkimTTLIssues[$selector] = $ttlIssues
        }
    }

    if ($result.DKIMFound) {
        $selectorsList = $result.DKIMSelectors -join ', '
        Write-Host "        DKIM records found: $selectorsList" -ForegroundColor Green

        # Validate DKIM syntax and status for each selector
        $totalSyntaxIssues = 0
        foreach ($selector in $result.DKIMSelectors) {
            if ($result.DKIMRecords.ContainsKey($selector)) {
                $dkimRecord = $result.DKIMRecords[$selector]

                # Syntax validation
                $syntaxIssues = Test-DKIMSyntax $dkimRecord $selector
                $result.DKIMSyntaxIssues[$selector] = $syntaxIssues
                $totalSyntaxIssues += $syntaxIssues.Count

                # Key length analysis
                $keyLengthInfo = Get-DKIMKeyLength $dkimRecord
                $result.DKIMKeyLengths[$selector] = $keyLengthInfo

                # All mechanism status check
                $allMechanism = Get-DKIMKeyStatus $dkimRecord
                $result.DKIMAllMechanisms[$selector] = $allMechanism

                if ($syntaxIssues.Count -gt 0) {
                    Write-Host "        $selector syntax issues: $($syntaxIssues.Count)" -ForegroundColor Yellow
                } else {
                    Write-Host "        $selector syntax validation: PASSED" -ForegroundColor Green
                }

                # Display key length information
                if ($keyLengthInfo.Error) {
                    Write-Host "        $selector key length: ERROR - $($keyLengthInfo.Error)" -ForegroundColor Red
                } else {
                    $keyLengthColor = if ($keyLengthInfo.IsWeak) { "Red" }
                    elseif ($keyLengthInfo.KeyLength -eq 1024) { "Yellow" }
                    else { "Green" }

                    $statusText = if ($keyLengthInfo.IsWeak) { " (WEAK - recommend 2048+ bits)" }
                    elseif ($keyLengthInfo.KeyLength -eq 1024) { " (WARNING - consider upgrading to 2048+ bits)" }
                    else { "" }

                    Write-Host "        $selector key length: $($keyLengthInfo.KeyLength) bits ($($keyLengthInfo.KeyType))$statusText" -ForegroundColor $keyLengthColor

                    # Add weakness to syntax issues if key is weak
                    if ($keyLengthInfo.IsWeak -and $keyLengthInfo.KeyLength -gt 0) {
                        $syntaxIssues += "Weak key length ($($keyLengthInfo.KeyLength) bits) - recommend 2048+ bits for better security"
                        $result.DKIMSyntaxIssues[$selector] = $syntaxIssues
                        $totalSyntaxIssues++
                    }

                    # Add recommendation for 1024-bit keys (warning, not weakness)
                    if ($keyLengthInfo.KeyLength -eq 1024) {
                        $recommendations += "Consider upgrading DKIM key to 2048+ bits for enhanced security (currently using 1024-bit key for selector '$selector') - DKIM Best Practices: https://dkim.org/info/dkim-faq.html"
                    }
                }

                # Display all mechanism status
                $statusColor = switch ($allMechanism) {
                    "ACTIVE" { "Green" }
                    "TESTING" { "Yellow" }
                    "REVOKED" { "Red" }
                    "UNKNOWN" { "Yellow" }
                    default { "White" }
                }
                Write-Host "        $selector status: $allMechanism" -ForegroundColor $statusColor

                # Display TTL validation results
                if ($result.DkimTTLIssues.ContainsKey($selector) -and $result.DkimTTLIssues[$selector].Count -gt 0) {
                    $ttlIssuesList = $result.DkimTTLIssues[$selector] -join '; '
                    Write-Host "        $selector TTL issues: $ttlIssuesList" -ForegroundColor Yellow
                } else {
                    Write-Host "        $selector TTL validation: PASSED" -ForegroundColor Green
                }
            }
        }

        $result.DKIMSyntaxValid = ($totalSyntaxIssues -eq 0)

        if ($totalSyntaxIssues -gt 0) {
            Write-Host "        Total DKIM syntax issues found: $totalSyntaxIssues" -ForegroundColor Yellow
        } else {
            Write-Host "        All DKIM syntax validation: PASSED" -ForegroundColor Green
        }

        # Display overall TTL validation summary
        $totalTTLIssues = 0
        foreach ($selector in $result.DKIMSelectors) {
            if ($result.DkimTTLIssues.ContainsKey($selector)) {
                $totalTTLIssues += $result.DkimTTLIssues[$selector].Count
            }
        }

        if ($totalTTLIssues -gt 0) {
            Write-Host "        Total DKIM TTL issues found: $totalTTLIssues" -ForegroundColor Yellow
        } else {
            Write-Host "        All DKIM TTL validation: PASSED" -ForegroundColor Green
        }

        # Enhanced DKIM Analysis
        Write-Host "        Running enhanced DKIM analysis..." -ForegroundColor Cyan

        # Service Provider Detection
        $providerInfo = Get-DKIMServiceProvider $result.DKIMRecords $domain
        $result | Add-Member -MemberType NoteProperty -Name "DKIMProviders" -Value $providerInfo

        if ($providerInfo.DetectedProviders.Count -gt 0) {
            Write-Host "        Service Provider: $($providerInfo.DetectedProviders -join ', ')" -ForegroundColor Cyan
        } else {
            Write-Host "        Service Provider: NOT IDENTIFIED (custom/self-hosted)" -ForegroundColor White
        }

        # Display selector1 and selector2 details if found
        if ($result.DKIMRecords.ContainsKey("selector1")) {
            Write-Host "        Selector1 Details: $($result.DKIMRecords['selector1'])" -ForegroundColor White
        }
        if ($result.DKIMRecords.ContainsKey("selector2")) {
            Write-Host "        Selector2 Details: $($result.DKIMRecords['selector2'])" -ForegroundColor White
        }
    } else {
        Write-Host "        No DKIM records found" -ForegroundColor Red
        # Initialize empty TTL issues for missing DKIM records
        $result.DkimTTLIssues = @{}
    }

    # CALCULATE SCORE AND STATUS
    $score = 0
    $recommendations = @()

    # SPF scoring (40 points total) - Granular check-based scoring
    # Record Present = 8 points, other 8 checks = 4 points each (8 + 8×4 = 40)
    $spfChecks = Get-ProtocolCheckDetails $result "SPF"
    foreach ($check in $spfChecks) {
        if ($check.Passed) {
            if ($check.Name -eq "Record Present") {
                $score += 8  # Record present check gets 8 points
            } else {
                $score += 4  # All other SPF checks get 4 points each
            }
        }
    }

    # Add recommendations for failed SPF checks
    if (-not $result.SPFFound) {
        $URLs = Get-ProviderSpecificURLs -Providers $result.MXProviders
        $recommendations += "Implement SPF record: $($URLs.SPFSetup)"
    } else {
        foreach ($issue in $result.SPFIssues) {
            $recommendation = Get-Recommendation -Issue $issue -Protocol "SPF" -Providers $result.MXProviders
            if (-not [string]::IsNullOrWhiteSpace($recommendation)) {
                $recommendations += $recommendation
            }
        }
    }

    # DMARC scoring (30 points total) - Granular check-based scoring
    # Each of the 5 DMARC checks = 6 points each (5×6 = 30)
    $dmarcChecks = Get-ProtocolCheckDetails $result "DMARC"
    foreach ($check in $dmarcChecks) {
        if ($check.Passed) {
            $score += 6  # Each DMARC check gets 6 points
        }
    }

    # Add recommendations for failed DMARC checks
    if (-not $result.DMARCFound) {
        $URLs = Get-ProviderSpecificURLs -Providers $result.MXProviders
        $recommendations += "Implement DMARC record with 'reject' policy: $($URLs.DMARCSetup)"
    } else {
        # Add specific recommendations based on policy weakness
        $URLs = Get-ProviderSpecificURLs -Providers $result.MXProviders
        if ($result.DMARCPolicy -ne "reject") {
            if ($result.DMARCPolicy -eq "quarantine") {
                $recommendations += "Upgrade DMARC policy from 'quarantine' to 'reject' for maximum security $($URLs.DMARCSetup)"
            } else {
                $recommendations += "Upgrade DMARC policy from 'none' to 'reject' $($URLs.DMARCSetup)"
            }
        }
        foreach ($issue in $result.DMARCIssues) {
            $recommendation = Get-Recommendation -Issue $issue -Protocol "DMARC" -Providers $result.MXProviders
            if (-not [string]::IsNullOrWhiteSpace($recommendation)) {
                $recommendations += $recommendation
            }
        }
    }

    # CHECK MX RECORDS
    Write-Host "  [4/4] Checking MX records..." -ForegroundColor White
    $mxAnalysis = Get-MXRecordAnalysis $domain

    # Populate MX results
    $result.MXFound = $mxAnalysis.MXFound
    $result.MXRecords = $mxAnalysis.MXRecords
    $result.MXMinTTL = $mxAnalysis.MinTTL
    $result.MXMaxTTL = $mxAnalysis.MaxTTL
    $result.MXAverageTTL = $mxAnalysis.AverageTTL
    $result.MXProviders = $mxAnalysis.MXProviders
    $result.MXPrimaryMX = $mxAnalysis.PrimaryMX
    $result.MXBackupMX = $mxAnalysis.BackupMX

    # DKIM scoring (30 points total) - Granular check-based scoring
    # Each of the 5 DKIM checks = 6 points each (5×6 = 30)
    $dkimChecks = Get-ProtocolCheckDetails $result "DKIM"
    foreach ($check in $dkimChecks) {
        if ($check.Passed) {
            $score += 6  # Each DKIM check gets 6 points
        }
    }

    # Add recommendations for failed DKIM checks
    if (-not $result.DKIMFound) {
        $URLs = Get-ProviderSpecificURLs -Providers $result.MXProviders
        $recommendations += "Implement DKIM record: $($URLs.DKIMSetup)"
    } else {
        if (-not $result.DKIMSyntaxValid) {
            $URLs = Get-ProviderSpecificURLs -Providers $result.MXProviders
            $recommendations += "Fix DKIM syntax errors: $($URLs.DKIMSetup)"
        }
        # Check for TTL issues
        $totalTTLIssues = 0
        foreach ($selector in $result.DKIMSelectors) {
            if ($result.DkimTTLIssues.ContainsKey($selector)) {
                $totalTTLIssues += $result.DkimTTLIssues[$selector].Count
            }
        }
        if ($totalTTLIssues -gt 0) {
            # Only show DKIM TTL recommendations for Microsoft/Office 365 providers
            if ($result.MXProviders -contains "Microsoft/Office 365") {
                $recommendations += "Fix DKIM TTL issues - consider increasing TTL to 3600+ seconds for better stability and to avoid any DNS timeout issues"
            }
        }
    }

    # Determine status with enhanced strictness for DMARC policy
    if ($score -ge 95 -and $result.DMARCPolicy -eq "reject") {
        $status = "Excellent"
        $statusColor = "Green"
    } elseif ($score -ge 85) {
        $status = "Good"
        $statusColor = "Cyan"
    } elseif ($score -ge 65) {
        $status = "Fair"
        $statusColor = "Yellow"
    } elseif ($score -ge 40) {
        $status = "Poor"
        $statusColor = "Red"
    } else {
        $status = "Critical"
        $statusColor = "DarkRed"
    }

    $result.Score = $score
    $result.Status = $status
    $result.Recommendations = $recommendations

    # Add email header authentication results if available (for option 4)
    if ($script:AuthenticationResults) {
        $result.EmailHeaderSPFResult = $script:AuthenticationResults.SPFResult
        $result.EmailHeaderDKIMResult = $script:AuthenticationResults.DKIMResult
        $result.EmailHeaderDMARCResult = $script:AuthenticationResults.DMARCResult
        $result.EmailHeaderAction = $script:AuthenticationResults.Action
        $result.EmailHeaderSMTPMailFrom = $script:AuthenticationResults.SMTPMailFrom
        $result.EmailHeaderHeaderFrom = $script:AuthenticationResults.HeaderFrom
        $result.EmailHeaderHeaderD = $script:AuthenticationResults.HeaderD
        $result.EmailHeaderCompAuth = $script:AuthenticationResults.CompAuth
        $result.EmailHeaderReason = $script:AuthenticationResults.Reason
        $result.EmailHeaderAuthenticationResultsRaw = $script:AuthenticationResults.AuthenticationResultsRaw
        $result.EmailHeaderDMARCPass = $script:AuthenticationResults.DMARCPass
        $result.EmailHeaderCondition1Met = $script:AuthenticationResults.Condition1Met
        $result.EmailHeaderCondition2Met = $script:AuthenticationResults.Condition2Met
        $result.EmailHeaderAntispamMailboxDelivery = $script:AuthenticationResults.AntispamMailboxDelivery
        $result.EmailHeaderAntispamUCF = $script:AuthenticationResults.AntispamUCF
        $result.EmailHeaderAntispamJMR = $script:AuthenticationResults.AntispamJMR
        $result.EmailHeaderAntispamDest = $script:AuthenticationResults.AntispamDest
        $result.EmailHeaderAntispamOFR = $script:AuthenticationResults.AntispamOFR
        $result.EmailHeaderOffice365FilteringCorrelationId = $script:AuthenticationResults.Office365FilteringCorrelationId
        $result.EmailHeaderForefrontAntispamReport = $script:AuthenticationResults.ForefrontAntispamReport
        $result.EmailHeaderForefrontCIP = $script:AuthenticationResults.ForefrontCIP
        $result.EmailHeaderForefrontCTRY = $script:AuthenticationResults.ForefrontCTRY
        $result.EmailHeaderForefrontLANG = $script:AuthenticationResults.ForefrontLANG
        $result.EmailHeaderForefrontSCL = $script:AuthenticationResults.ForefrontSCL
        $result.EmailHeaderForefrontSRV = $script:AuthenticationResults.ForefrontSRV
        $result.EmailHeaderForefrontIPV = $script:AuthenticationResults.ForefrontIPV
        $result.EmailHeaderForefrontSFV = $script:AuthenticationResults.ForefrontSFV
        $result.EmailHeaderForefrontPTR = $script:AuthenticationResults.ForefrontPTR
        $result.EmailHeaderForefrontCAT = $script:AuthenticationResults.ForefrontCAT
        $result.EmailHeaderForefrontDIR = $script:AuthenticationResults.ForefrontDIR
        $result.EmailHeaderForefrontSFP = $script:AuthenticationResults.ForefrontSFP
    }

    # Display summary
    Write-Host ""
    Write-Host "  SUMMARY FOR $domain" -ForegroundColor Cyan
    Write-Host "  Score: $score/100 ($status)" -ForegroundColor $statusColor
    Write-Host "  SPF: $(if($result.SPFFound){'FOUND'}else{'MISSING'})" -NoNewline
    Write-Host " | DMARC: $(if($result.DMARCFound){'FOUND'}else{'MISSING'})" -NoNewline
    Write-Host " | DKIM: $(if($result.DKIMFound){'FOUND'}else{'MISSING'})"

    # Display email header results if available (only for option 4)
    if ($menuChoice -eq '4' -and $script:AuthenticationResults) {
        Write-Host ""
        Write-Host "  EMAIL HEADER ANALYSIS:" -ForegroundColor Yellow
        Write-Host "  SPF Result: $($result.EmailHeaderSPFResult)" -ForegroundColor $(if ($result.EmailHeaderSPFResult -eq 'pass') { 'Green' }else { 'Red' })
        Write-Host "  DKIM Result: $($result.EmailHeaderDKIMResult)" -ForegroundColor $(if ($result.EmailHeaderDKIMResult -eq 'pass') { 'Green' }else { 'Red' })
        Write-Host "  DMARC Result: $($result.EmailHeaderDMARCResult)" -ForegroundColor $(if ($result.EmailHeaderDMARCResult -eq 'pass') { 'Green' }else { 'Red' })
        Write-Host "  DMARC Pass: $($result.EmailHeaderDMARCPass)" -ForegroundColor $(if ($result.EmailHeaderDMARCPass -eq 'Yes') { 'Green' }else { 'Red' }) -BackgroundColor $(if ($result.EmailHeaderDMARCPass -eq 'Yes') { 'DarkGreen' }else { 'DarkRed' })
    }

    if ($recommendations.Count -gt 0) {
        Write-Host "  Recommendations:" -ForegroundColor Yellow
        foreach ($rec in $recommendations) {
            Write-Host "    - $rec" -ForegroundColor Yellow
        }
    }
    Write-Host ""
    $allResults += $result
}

# === Use provided output path or default to current directory ===
if ($OutputPath -and $OutputPath -ne ".") {
    $path = $OutputPath
} else {
    $path = "."  # Default to current directory
    Write-Host "Using current directory for output. Use -OutputPath parameter to specify a different location." -ForegroundColor Yellow
}

# === Create directory if it doesn't exist ===
if (-not (Test-Path -Path $path)) {
    New-Item -ItemType Directory -Path $path -Force | Out-Null
}

Write-Host ""
Write-Host "Generating HTML report..." -ForegroundColor Green

# Generate timestamps and statistics
$reportDate = Get-Date -Format "MMMM d, yyyy"
$fileTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"

# Calculate overall statistics
$totalDomains = $allResults.Count
$avgScore = if ($totalDomains -gt 0) { [math]::Round(($allResults | Measure-Object -Property Score -Average).Average, 1) } else { 0 }

# Add check percentages to results
foreach ($result in $allResults) {
    $spfPercentage = Get-ProtocolCheckPercentage $result "SPF"
    $dmarcPercentage = Get-ProtocolCheckPercentage $result "DMARC"
    $dkimPercentage = Get-ProtocolCheckPercentage $result "DKIM"

    $result | Add-Member -MemberType NoteProperty -Name "SPFCheckPercentage" -Value $spfPercentage
    $result | Add-Member -MemberType NoteProperty -Name "DMARCCheckPercentage" -Value $dmarcPercentage
    $result | Add-Member -MemberType NoteProperty -Name "DKIMCheckPercentage" -Value $dkimPercentage
}

# Start building HTML content
$html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Email Authentication Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f7fa;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }
        .header h1 {
            margin:  0;
            font-size: 2.5em;
            font-weight: 300;
        }
        .header p {
            margin: 10px 0 0 0;
            opacity: 0.9;
            font-size: 1.1em;
        }
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: white;
            padding: 25px;
            border-radius:  12px;
            box-shadow: 0 3px 10px rgba(0,0,0,0.1);
            text-align: center;
            border-left: 5px solid #b200ff;
        }
        .summary-card h3 {
            margin: 0 0 10px 0;
            color: #495057;
            font-size: 1.1em;
        }
        .summary-card .number {
            font-size: 2.5em;
            font-weight: bold;
            color: #007bff;
            margin: 10px 0;
        }
        .domain-section {
            background: white;
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 3px 15px rgba(0,0,0,0.1);
            border-left: 5px solid #28a745;
        }
        .domain-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 15px;
        }
        .domain-name {
            font-size: 1.8em;
            font-weight: 600;
            color: #2c3e50;
            margin: 0;
        }
        .score-section {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .status-excellent { color: #28a745; font-weight: bold; }
        .status-good { color: #17a2b8; font-weight: bold; }
        .status-fair { color: #ffc107; font-weight: bold; }
        .status-poor { color: #fd7e14; font-weight: bold; }
        .status-critical { color: #dc3545; font-weight: bold; }
        .record-found { color: #28a745; font-weight: 600; }
        .record-missing { color: #dc3545; font-weight: 600; }
        .auth-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .auth-table th, .auth-table td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #e9ecef;
        }
        .auth-table th {
            background-color: #f8f9fa;
        }
        .auth-table tr:hover {
            background-color: #f8f9fa;
        }
        .auth-table .record-type {
            vertical-align: top;
            width: 20%;
            font-weight: bold;
        }
        .auth-table .record-value {
            vertical-align: top;
            line-height: 1.5;
            word-break: break-all;
            max-width: 0;
        }

        /* Email Header Analysis Table Styles */
        .email-header-section {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 25%, #e74c3c 50%, #c0392b 75%, #8e44ad 100%);
            background-size: 400% 400%;
            animation: emailSecurityGradient 8s ease infinite;
            border-radius: 20px;
            padding: 35px;
            margin: 30px 0;
            box-shadow:
                0 20px 40px rgba(231, 76, 60, 0.3),
                0 0 60px rgba(142, 68, 173, 0.2),
                inset 0 1px 0 rgba(255,255,255,0.1);
            color: white;
            position: relative;
            overflow: hidden;
        }
        .email-header-section::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background:
                radial-gradient(circle at 20% 20%, rgba(255,255,255,0.1) 0%, transparent 50%),
                radial-gradient(circle at 80% 80%, rgba(255,255,255,0.08) 0%, transparent 50%),
                radial-gradient(circle at 40% 60%, rgba(52, 152, 219, 0.1) 0%, transparent 50%);
            pointer-events: none;
            animation: emailPatternMove 12s ease-in-out infinite;
        }
        .email-header-section::after {
            position: absolute;
            top: 15px;
            right: 20px;
            font-size: 1.2em;
            opacity: 0.2;
            animation: securityIconsFloat 6s ease-in-out infinite;
            letter-spacing: 10px;
        }
        @keyframes emailSecurityGradient {
            0% { background-position: 0% 50%; }
            25% { background-position: 100% 50%; }
            50% { background-position: 100% 100%; }
            75% { background-position: 0% 100%; }
            100% { background-position: 0% 50%; }
        }
        @keyframes emailPatternMove {
            0%, 100% {
                transform: translateX(0) translateY(0);
                opacity: 0.3;
            }
            33% {
                transform: translateX(10px) translateY(-5px);
                opacity: 0.5;
            }
            66% {
                transform: translateX(-5px) translateY(10px);
                opacity: 0.4;
            }
        }
        @keyframes securityIconsFloat {
            0%, 100% {
                transform: translateY(0px) rotate(0deg);
                opacity: 0.2;
            }
            50% {
                transform: translateY(-8px) rotate(2deg);
                opacity: 0.3;
            }
        }
        .email-header-title {
            display: flex;
            align-items: center;
            gap: 20px;
            margin-bottom: 25px;
            font-size: 1.6em;
            font-weight: 700;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
            position: relative;
            z-index: 2;
        }
        .email-header-icon {
            font-size: 1.4em;
            background: linear-gradient(135deg, rgba(255,255,255,0.25), rgba(255,255,255,0.15));
            padding: 15px;
            border-radius: 12px;
            box-shadow:
                0 8px 16px rgba(0,0,0,0.2),
                inset 0 1px 0 rgba(255,255,255,0.3);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.2);
            transition: all 0.3s ease;
        }
        .email-header-icon:hover {
            transform: scale(1.05) rotate(5deg);
            background: linear-gradient(135deg, rgba(255,255,255,0.35), rgba(255,255,255,0.25));
            box-shadow:
                0 12px 24px rgba(0,0,0,0.3),
                inset 0 1px 0 rgba(255,255,255,0.4);
        }
        .header-analysis-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        .header-analysis-card {
            background: linear-gradient(135deg, rgba(255,255,255,0.98) 0%, rgba(255,255,255,0.95) 100%);
            color: #2c3e50;
            border-radius: 15px;
            padding: 25px;
            box-shadow:
                0 10px 30px rgba(0,0,0,0.15),
                0 0 20px rgba(255,255,255,0.1);
            transition: all 0.4s ease;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.3);
            position: relative;
            overflow: hidden;
        }
        .header-analysis-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, #3498db, #e74c3c, #9b59b6, #f39c12);
            background-size: 300% 100%;
            animation: cardBorderFlow 4s ease-in-out infinite;
        }
        @keyframes cardBorderFlow {
            0%, 100% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
        }
        .header-analysis-card:hover {
            transform: translateY(-8px) scale(1.02);
            box-shadow:
                0 20px 40px rgba(0,0,0,0.2),
                0 0 30px rgba(255,255,255,0.2);
        }
        .header-card-title {
            font-size: 1.1em;
            font-weight: 600;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .header-results-table {
            width: 100%;
            border-collapse: collapse;
        }
        .header-results-table td {
            padding: 12px 8px;
            border-bottom: 1px solid #e9ecef;
            vertical-align: middle;
        }
        .header-results-table td:first-child {
            font-weight: 600;
            color: #495057;
            width: 40%;
        }
        .header-result-value {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .result-status-icon {
            font-size: 1.1em;
            font-weight: bold;
        }
        .result-pass {
            color: #28a745;
        }
        .result-fail {
            color: #dc3545;
        }
        .result-none {
            color: #6c757d;
        }
        .result-unknown {
            color: #ffc107;
        }
        .dmarc-pass-highlight {
            background: linear-gradient(135deg, #28a745, #20c997);
            color: white;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            text-align: center;
            box-shadow: 0 2px 8px rgba(40, 167, 69, 0.3);
            animation: pulse-glow 2s infinite;
        }
        .dmarc-fail-highlight {
            background: linear-gradient(135deg, #dc3545, #c82333);
            color: white;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            text-align: center;
            box-shadow: 0 2px 8px rgba(220, 53, 69, 0.3);
        }
        @keyframes pulse-glow {
            0%, 100% { box-shadow: 0 2px 8px rgba(40, 167, 69, 0.3); }
            50% { box-shadow: 0 4px 20px rgba(40, 167, 69, 0.6); }
        }
        .header-domain-info {
            background: linear-gradient(135deg, rgba(255,255,255,0.15), rgba(255,255,255,0.08));
            border-radius: 12px;
            padding: 20px;
            margin-top: 20px;
            backdrop-filter: blur(15px);
            border: 1px solid rgba(255,255,255,0.2);
            box-shadow:
                0 8px 16px rgba(0,0,0,0.1),
                inset 0 1px 0 rgba(255,255,255,0.2);
        }
        .domain-comparison {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-top: 15px;
        }
        .domain-item {
            background: linear-gradient(135deg, rgba(255,255,255,0.2), rgba(255,255,255,0.1));
            padding: 15px;
            border-radius: 10px;
            font-size: 0.95em;
            backdrop-filter: blur(8px);
            border: 1px solid rgba(255,255,255,0.15);
            transition: all 0.3s ease;
        }
        .domain-item:hover {
            background: linear-gradient(135deg, rgba(255,255,255,0.25), rgba(255,255,255,0.15));
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        .domain-label {
            font-weight: 700;
            margin-bottom: 8px;
            opacity: 0.95;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .domain-value {
            font-family: 'Courier New', Monaco, 'Lucida Console', monospace;
            background: linear-gradient(135deg, rgba(0,0,0,0.15), rgba(0,0,0,0.1));
            padding: 8px 12px;
            border-radius: 6px;
            word-break: break-all;
            font-size: 0.9em;
            border: 1px solid rgba(0,0,0,0.1);
        }

        /* Enhanced DMARC Condition Styles */
        .condition-card {
            background: linear-gradient(135deg, rgba(255,255,255,0.15), rgba(255,255,255,0.08));
            border-radius: 12px;
            padding: 18px;
            margin: 12px 0;
            border-left: 4px solid transparent;
            backdrop-filter: blur(8px);
            transition: all 0.3s ease;
        }
        .condition-card:hover {
            transform: translateX(5px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        }
        .condition-met {
            border-left-color: #28a745;
            background: linear-gradient(135deg, rgba(40, 167, 69, 0.15), rgba(32, 201, 151, 0.08));
        }
        .condition-not-met {
            border-left-color: #dc3545;
            background: linear-gradient(135deg, rgba(220, 53, 69, 0.15), rgba(200, 35, 51, 0.08));
        }
        .condition-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 10px;
            font-weight: 700;
            font-size: 1em;
        }
        .condition-status-badge {
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            box-shadow: 0 3px 10px rgba(0,0,0,0.2);
        }
        .condition-status-met {
            background: linear-gradient(135deg, #28a745, #20c997);
            color: white;
            animation: condition-success-pulse 2s infinite;
        }
        .condition-status-not-met {
            background: linear-gradient(135deg, #dc3545, #c82333);
            color: white;
        }
        @keyframes condition-success-pulse {
            0%, 100% {
                box-shadow: 0 3px 10px rgba(40, 167, 69, 0.3);
                transform: scale(1);
            }
            50% {
                box-shadow: 0 6px 20px rgba(40, 167, 69, 0.6);
                transform: scale(1.05);
            }
        }
        .condition-details {
            font-size: 0.9em;
            line-height: 1.5;
            opacity: 0.95;
        }
        .condition-check-item {
            display: flex;
            align-items: center;
            gap: 8px;
            margin: 6px 0;
            padding: 4px 0;
        }
        .condition-check-icon {
            font-size: 1.1em;
            font-weight: bold;
            min-width: 20px;
        }
        .condition-check-pass {
            color: #28a745;
        }
        .condition-check-fail {
            color: #dc3545;
        }

        /* New User-Friendly Email Header Analysis Styles */
        .email-header-main-title {
            display: flex;
            align-items: center;
            gap: 20px;
            margin-bottom: 30px;
            padding: 25px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 15px;
            color: white;
            box-shadow: 0 10px 30px rgba(102, 126, 234, 0.3);
        }
        .main-title-icon {
            font-size: 2.5em;
            background: rgba(255,255,255,0.2);
            padding: 15px;
            border-radius: 50%;
            animation: float 3s ease-in-out infinite;
        }
        @keyframes float {
            0%, 100% { transform: translateY(0px); }
            50% { transform: translateY(-10px); }
        }
        .main-title-content h2 {
            margin: 0;
            font-size: 2em;
            font-weight: 700;
            text-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }
        .main-title-subtitle {
            margin: 5px 0 0 0;
            font-size: 1.1em;
            opacity: 0.9;
            font-weight: 300;
        }

        .overall-result-banner {
            border-radius: 15px;
            padding: 25px;
            margin: 25px 0;
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
            backdrop-filter: blur(10px);
        }
        .result-banner-pass {
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
            border: 2px solid rgba(40, 167, 69, 0.3);
        }
        .result-banner-fail {
            background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
            border: 2px solid rgba(220, 53, 69, 0.3);
        }
        .result-banner-neutral {
            background: linear-gradient(135deg, #6c757d 0%, #495057 100%);
            border: 2px solid rgba(108, 117, 125, 0.3);
        }
        .result-banner-content {
            display: flex;
            align-items: center;
            gap: 20px;
            color: white;
        }
        .result-banner-icon {
            font-size: 3em;
            background: rgba(255,255,255,0.2);
            padding: 20px;
            border-radius: 50%;
            animation: result-pulse 2s infinite;
        }
        @keyframes result-pulse {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.1); opacity: 0.8; }
        }
        .result-banner-main {
            font-size: 1.8em;
            font-weight: 800;
            margin-bottom: 8px;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        .result-banner-detail {
            font-size: 1.1em;
            opacity: 0.9;
            line-height: 1.4;
        }

        .auth-flow-container {
            background: white;
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            margin: 25px 0;
        }
        .flow-title {
            font-size: 1.6em;
            font-weight: 700;
            color: #2c3e50;
            margin-bottom: 30px;
            text-align: center;
            padding-bottom: 15px;
            border-bottom: 3px solid #e9ecef;
        }
        .auth-step {
            margin: 40px 0;
            position: relative;
        }
        .auth-step::before {
            content: '';
            position: absolute;
            left: 35px;
            top: 50px;
            bottom: -20px;
            width: 2px;
            background: linear-gradient(to bottom, #007bff, #6c757d);
            opacity: 0.3;
        }
        .auth-step:last-child::before {
            display: none;
        }
        .step-header {
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 25px;
        }
        .step-number {
            display: flex;
            align-items: center;
            justify-content: center;
            width: 50px;
            height: 50px;
            background: linear-gradient(135deg, #007bff, #6610f2);
            color: white;
            border-radius: 50%;
            font-size: 1.3em;
            font-weight: 800;
            box-shadow: 0 4px 15px rgba(0, 123, 255, 0.3);
            position: relative;
            z-index: 2;
        }
        .step-title {
            font-size: 1.3em;
            font-weight: 600;
            color: #2c3e50;
        }

        .protocol-results-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 25px;
            margin: 20px 0;
        }
        .protocol-card {
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
            transition: all 0.3s ease;
            border-top: 4px solid transparent;
        }
        .protocol-card:hover {
            transform: translateY(-8px);
            box-shadow: 0 15px 35px rgba(0,0,0,0.15);
        }
        .protocol-card:nth-child(1) { border-top-color: #28a745; }
        .protocol-card:nth-child(2) { border-top-color: #6f42c1; }
        .protocol-card:nth-child(3) { border-top-color: #fd7e14; }
        .protocol-icon {
            font-size: 2.5em;
            margin-bottom: 15px;
            padding: 20px;
            border-radius: 50%;
            color: white;
            display: inline-block;
        }
        .spf-icon {
            background: linear-gradient(135deg, #28a745, #20c997);
        }
        .dkim-icon {
            background: linear-gradient(135deg, #6f42c1, #e83e8c);
        }
        .dmarc-icon {
            background: linear-gradient(135deg, #fd7e14, #ffc107);
        }
        .protocol-name {
            font-size: 1.4em;
            font-weight: 700;
            color: #2c3e50;
            margin-bottom: 5px;
        }
        .protocol-description {
            font-size: 0.9em;
            color: #6c757d;
            margin-bottom: 20px;
        }
        .protocol-result {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            padding: 12px 20px;
            border-radius: 25px;
            font-weight: 700;
            margin-bottom: 15px;
        }
        .protocol-pass {
            background: linear-gradient(135deg, #28a745, #20c997);
            color: white;
            box-shadow: 0 4px 15px rgba(40, 167, 69, 0.3);
        }
        .protocol-fail {
            background: linear-gradient(135deg, #dc3545, #c82333);
            color: white;
            box-shadow: 0 4px 15px rgba(220, 53, 69, 0.3);
        }
        .protocol-unknown {
            background: linear-gradient(135deg, #ffc107, #fd7e14);
            color: white;
            box-shadow: 0 4px 15px rgba(255, 193, 7, 0.3);
        }
        .protocol-status-icon {
            font-size: 1.2em;
        }
        .protocol-explanation {
            font-size: 0.85em;
            color: #495057;
            line-height: 1.4;
            font-style: italic;
        }

        .domain-alignment-explanation {
            background: #f8f9fa;
            border-left: 4px solid #007bff;
            padding: 15px 20px;
            margin: 20px 0;
            border-radius: 8px;
            font-size: 0.95em;
            color: #495057;
        }
        .domain-comparison-modern {
            display: flex;
            flex-direction: column;
            gap: 30px;
            margin: 25px 0;
        }
        .domain-pair {
            display: grid;
            grid-template-columns: 1fr auto 1fr;
            gap: 20px;
            align-items: center;
        }
        .domain-info-card {
            background: linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%);
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 3px 15px rgba(0,0,0,0.08);
            text-align: center;
            border: 2px solid #e9ecef;
            transition: all 0.3s ease;
        }
        .domain-info-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.12);
            border-color: #007bff;
        }
        .domain-card-header {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            margin-bottom: 15px;
        }
        .domain-icon {
            font-size: 1.5em;
            color: #007bff;
        }
        .domain-type {
            font-weight: 600;
            color: #2c3e50;
            font-size: 1.1em;
        }
        .domain-value-display {
            font-family: 'Courier New', monospace;
            background: #e9ecef;
            padding: 12px 16px;
            border-radius: 8px;
            font-weight: 600;
            color: #495057;
            margin-bottom: 10px;
            word-break: break-all;
            border: 1px solid #dee2e6;
        }
        .domain-description {
            font-size: 0.85em;
            color: #6c757d;
            line-height: 1.3;
        }
        .alignment-arrow {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 5px;
            color: #007bff;
        }
        .arrow-icon {
            font-size: 2em;
            font-weight: bold;
        }
        .alignment-text {
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .alignment-status {
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .alignment-result {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 12px 20px;
            border-radius: 25px;
            font-weight: 700;
            font-size: 1.1em;
        }
        .alignment-pass {
            background: linear-gradient(135deg, #28a745, #20c997);
            color: white;
            box-shadow: 0 4px 15px rgba(40, 167, 69, 0.3);
        }
        .alignment-fail {
            background: linear-gradient(135deg, #dc3545, #c82333);
            color: white;
            box-shadow: 0 4px 15px rgba(220, 53, 69, 0.3);
        }

        .dmarc-conditions-explanation {
            background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%);
            border-left: 4px solid #2196f3;
            padding: 20px;
            margin: 25px 0;
            border-radius: 10px;
            color: #1565c0;
        }
        .dmarc-conditions-explanation p {
            margin: 0;
            font-size: 1.05em;
            font-weight: 500;
        }
        .conditions-container {
            display: flex;
            flex-direction: column;
            gap: 20px;
            margin: 25px 0;
        }
        .condition-modern {
            background: linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%);
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
            border: 2px solid transparent;
            transition: all 0.3s ease;
        }
        .condition-modern:hover {
            transform: translateY(-3px);
            box-shadow: 0 15px 35px rgba(0,0,0,0.12);
        }
        .condition-success {
            border-color: #28a745;
            background: linear-gradient(135deg, #f8fff9 0%, #e8f5e8 100%);
        }
        .condition-failure {
            border-color: #dc3545;
            background: linear-gradient(135deg, #fff8f8 0%, #f5e8e8 100%);
        }
        .condition-main-header {
            display: grid;
            grid-template-columns: auto 1fr auto;
            gap: 20px;
            align-items: center;
            margin-bottom: 20px;
        }
        .condition-number {
            display: flex;
            align-items: center;
            justify-content: center;
            width: 50px;
            height: 50px;
            background: linear-gradient(135deg, #6c757d, #495057);
            color: white;
            border-radius: 50%;
            font-size: 1.4em;
            font-weight: 800;
            box-shadow: 0 4px 15px rgba(108, 117, 125, 0.3);
        }
        .condition-success .condition-number {
            background: linear-gradient(135deg, #28a745, #20c997);
        }
        .condition-failure .condition-number {
            background: linear-gradient(135deg, #dc3545, #c82333);
        }
        .condition-title-section {
            text-align: left;
        }
        .condition-title {
            font-size: 1.3em;
            font-weight: 700;
            color: #2c3e50;
            margin-bottom: 5px;
        }
        .condition-subtitle {
            font-size: 0.95em;
            color: #6c757d;
            font-weight: 500;
        }
        .condition-main-status {
            text-align: right;
        }
        .main-status-badge {
            padding: 10px 20px;
            border-radius: 25px;
            font-size: 1em;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }
        .status-met {
            background: linear-gradient(135deg, #28a745, #20c997);
            color: white;
            animation: success-glow 2s infinite;
        }
        .status-not-met {
            background: linear-gradient(135deg, #dc3545, #c82333);
            color: white;
        }
        @keyframes success-glow {
            0%, 100% { box-shadow: 0 4px 15px rgba(40, 167, 69, 0.3); }
            50% { box-shadow: 0 8px 30px rgba(40, 167, 69, 0.6); }
        }
        .condition-requirements {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }
        .requirement-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 15px 20px;
            background: rgba(255,255,255,0.8);
            border-radius: 10px;
            border: 1px solid #e9ecef;
            transition: all 0.3s ease;
        }
        .requirement-item:hover {
            transform: translateX(5px);
            box-shadow: 0 3px 10px rgba(0,0,0,0.1);
        }
        .requirement-met {
            border-left: 4px solid #28a745;
            background: linear-gradient(135deg, rgba(40, 167, 69, 0.05), rgba(255,255,255,0.8));
        }
        .requirement-not-met {
            border-left: 4px solid #dc3545;
            background: linear-gradient(135deg, rgba(220, 53, 69, 0.05), rgba(255,255,255,0.8));
        }
        .requirement-icon {
            font-size: 1.3em;
            font-weight: bold;
            min-width: 20px;
        }
        .requirement-text {
            font-size: 1em;
            font-weight: 500;
            color: #2c3e50;
        }
        .or-separator {
            text-align: center;
            margin: 15px 0;
            position: relative;
        }
        .or-separator::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 0;
            right: 0;
            height: 1px;
            background: #dee2e6;
            z-index: 1;
        }
        .or-text {
            background: #ffffff;
            padding: 10px 20px;
            border-radius: 25px;
            border: 2px solid #dee2e6;
            font-weight: 700;
            color: #6c757d;
            position: relative;
            z-index: 2;
            font-size: 1.1em;
        }

        .final-result-modern {
            margin: 30px 0;
            text-align: center;
        }
        .final-result-content {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 25px;
            padding: 30px;
            border-radius: 20px;
            backdrop-filter: blur(10px);
            border: 3px solid transparent;
        }
        .final-success {
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
            border-color: rgba(40, 167, 69, 0.3);
            color: white;
            box-shadow: 0 10px 30px rgba(40, 167, 69, 0.3);
        }
        .final-failure {
            background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
            border-color: rgba(220, 53, 69, 0.3);
            color: white;
            box-shadow: 0 10px 30px rgba(220, 53, 69, 0.3);
        }
        .final-result-icon {
            font-size: 4em;
            animation: final-bounce 2s infinite;
        }
        @keyframes final-bounce {
            0%, 20%, 50%, 80%, 100% { transform: translateY(0); }
            40% { transform: translateY(-10px); }
            60% { transform: translateY(-5px); }
        }
        .final-result-text {
            text-align: left;
            flex: 1;
        }
        .final-result-title {
            font-size: 1.8em;
            font-weight: 800;
            margin-bottom: 10px;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        .final-result-explanation {
            font-size: 1.1em;
            opacity: 0.95;
            line-height: 1.5;
            font-weight: 400;
        }

        /* Responsive Design for Mobile */
        @media (max-width: 768px) {
            .protocol-results-grid {
                grid-template-columns: 1fr;
            }
            .domain-pair {
                grid-template-columns: 1fr;
                text-align: center;
            }
            .alignment-arrow {
                transform: rotate(90deg);
            }
            .condition-main-header {
                grid-template-columns: 1fr;
                text-align: center;
                gap: 15px;
            }
            .final-result-content {
                flex-direction: column;
                text-align: center;
            }
            .final-result-text {
                text-align: center;
            }
        }

        /* Modern Authentication Process Breakdown Styles */
        .auth-flow-container-clear {
            background: rgba(255,255,255,0.05);
            border-radius: 12px;
            padding: 20px;
            margin: 20px 0;
        }
        .flow-title-modern {
            text-align: center;
            margin-bottom: 30px;
            color: white;
        }
        .flow-icon {
            font-size: 2em;
            margin-bottom: 10px;
            display: block;
        }
        .flow-title-modern h3 {
            margin: 5px 0;
            font-size: 1.6em;
            font-weight: 700;
        }
        .flow-subtitle {
            font-size: 1em;
            opacity: 0.9;
            margin: 0;
        }
        .auth-step-clear {
            background: rgba(255,255,255,0.95);
            color: #2c3e50;
            border-radius: 12px;
            margin: 25px 0;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            overflow: hidden;
            position: relative;
        }
        .auth-step-clear::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        }
        .step-1::before {
            background: linear-gradient(90deg, #28a745 0%, #20c997 100%);
        }
        .step-2::before {
            background: linear-gradient(90deg, #007bff 0%, #6610f2 100%);
        }
        .step-3::before {
            background: linear-gradient(90deg, #fd7e14 0%, #e83e8c 100%);
        }
        .step-4::before {
            background: linear-gradient(90deg, #6f42c1 0%, #e83e8c 100%);
        }
        .step-header-modern {
            display: flex;
            align-items: flex-start;
            gap: 15px;
            padding: 20px 25px 15px;
            background: rgba(248,249,250,0.5);
            border-bottom: 1px solid rgba(0,0,0,0.1);
        }
        .step-indicator {
            display: flex;
            flex-direction: column;
            align-items: center;
            position: relative;
        }
        .step-number-modern {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 1.2em;
            box-shadow: 0 3px 10px rgba(0,0,0,0.2);
        }
        .step-1 .step-number-modern {
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
        }
        .step-2 .step-number-modern {
            background: linear-gradient(135deg, #007bff 0%, #6610f2 100%);
        }
        .step-3 .step-number-modern {
            background: linear-gradient(135deg, #fd7e14 0%, #e83e8c 100%);
        }
        .step-4 .step-number-modern {
            background: linear-gradient(135deg, #6f42c1 0%, #e83e8c 100%);
        }
        .step-connector {
            width: 2px;
            height: 30px;
            background: linear-gradient(to bottom, rgba(102,126,234,0.3), transparent);
            margin-top: 10px;
        }
        .step-4 .step-connector {
            display: none;
        }
        .step-content-header {
            flex: 1;
        }
        .step-title-modern {
            margin: 0 0 5px 0;
            font-size: 1.3em;
            font-weight: 700;
            color: #2c3e50;
        }
        .step-description {
            margin: 0;
            font-size: 0.95em;
            color: #6c757d;
        }
        .step-body {
            padding: 20px 25px 25px;
        }
        .info-box {
            background: rgba(23,162,184,0.1);
            border-left: 4px solid #17a2b8;
            padding: 12px 15px;
            margin-bottom: 20px;
            border-radius: 0 6px 6px 0;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .info-icon {
            font-size: 1.2em;
        }
        .protocol-results-grid-modern {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
        }
        .protocol-card-modern {
            background: white;
            border: 2px solid #e9ecef;
            border-radius: 10px;
            padding: 20px;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        .protocol-card-modern:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        }
        .spf-card {
            border-color: #28a745;
        }
        .dkim-card {
            border-color: #6f42c1;
        }
        .dmarc-card {
            border-color: #007bff;
        }
        .protocol-header-modern {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 15px;
        }
        .protocol-icon-modern {
            font-size: 2em;
            padding: 10px;
            border-radius: 8px;
            color: white;
        }
        .spf-icon-modern {
            background: linear-gradient(135deg, #28a745, #20c997);
        }
        .dkim-icon-modern {
            background: linear-gradient(135deg, #6f42c1, #e83e8c);
        }
        .dmarc-icon-modern {
            background: linear-gradient(135deg, #007bff, #6610f2);
        }
        .action-icon-modern {
            background: linear-gradient(135deg, #fd7e14, #ffb347);
        }
        .compauth-icon-modern {
            background: linear-gradient(135deg, #17a2b8, #20c997);
        }
        .reason-icon-modern {
            background: linear-gradient(135deg, #ffc107, #fd7e14);
        }
        .ucf-icon-modern {
            background: linear-gradient(135deg, #667eea, #764ba2);
        }
        .jmr-icon-modern {
            background: linear-gradient(135deg, #f093fb, #f5576c);
        }
        .dest-icon-modern {
            background: linear-gradient(135deg, #4facfe, #00f2fe);
        }
        .ofr-icon-modern {
            background: linear-gradient(135deg, #fa709a, #fee140);
        }
        .compauth-card {
            border-color: #17a2b8;
        }
        .action-card {
            border-color: #fd7e14;
        }
        .reason-card {
            border-color: #ffc107;
        }
        .ucf-card {
            border-color: #667eea;
        }
        .jmr-card {
            border-color: #f093fb;
        }
        .dest-card {
            border-color: #4facfe;
        }
        .ofr-card {
            border-color: #fa709a;
        }
        .protocol-info {
            flex: 1;
        }
        .protocol-name-modern {
            font-size: 1.3em;
            font-weight: 700;
            color: #2c3e50;
        }
        .protocol-description-modern {
            font-size: 0.9em;
            color: #6c757d;
        }
        .protocol-result-modern {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 10px;
            padding: 8px 12px;
            border-radius: 6px;
            font-weight: 600;
        }
        .protocol-info-modern {
            background: rgba(108,117,125,0.1);
            color: #495057;
            border: 1px solid rgba(108,117,125,0.3);
        }
        .protocol-pass-modern {
            background: rgba(40,167,69,0.1);
            color: #155724;
            border: 1px solid rgba(40,167,69,0.3);
        }
        .protocol-fail-modern {
            background: rgba(220,53,69,0.1);
            color: #721c24;
            border: 1px solid rgba(220,53,69,0.3);
        }
        .protocol-warn-modern {
            background: rgba(255,193,7,0.1);
            color: #856404;
            border: 1px solid rgba(255,193,7,0.3);
        }
        .protocol-unknown-modern {
            background: rgba(108,117,125,0.1);
            color: #495057;
            border: 1px solid rgba(108,117,125,0.3);
        }
        .protocol-status-icon-modern {
            font-size: 1.1em;
        }
        .protocol-explanation-modern {
            font-size: 0.9em;
            color: #6c757d;
            line-height: 1.4;
        }
        .domain-alignment-explanation-modern {
            margin-bottom: 20px;
        }
        .domain-comparison-ultra-modern {
            display: flex;
            flex-direction: column;
            gap: 25px;
        }
        .domain-pair-modern {
            display: grid;
            grid-template-columns: 1fr auto 1fr;
            gap: 20px;
            align-items: center;
        }
        .domain-pair-modern.single-pair {
            grid-template-columns: 1fr auto 1fr auto;
            gap: 15px;
        }
        .domain-info-card-modern {
            background: white;
            border: 2px solid #e9ecef;
            border-radius: 10px;
            padding: 15px;
            text-align: center;
        }
        .envelope-card {
            border-color: #17a2b8;
        }
        .header-card {
            border-color: #28a745;
        }
        .dkim-card {
            border-color: #6f42c1;
        }
        .domain-card-header-modern {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 10px;
            justify-content: center;
        }
        .domain-icon-modern {
            font-size: 1.5em;
            color: #007bff;
        }
        .domain-type-info {
            text-align: left;
        }
        .domain-type-modern {
            font-weight: 600;
            font-size: 0.9em;
            color: #2c3e50;
            display: block;
        }
        .domain-type-desc {
            font-size: 0.8em;
            color: #6c757d;
            display: block;
        }
        .domain-value-display-modern {
            background: rgba(0,123,255,0.1);
            border: 1px solid rgba(0,123,255,0.3);
            border-radius: 6px;
            padding: 8px 12px;
            font-family: monospace;
            font-weight: 600;
            color: #0056b3;
            word-break: break-all;
        }
        .alignment-arrow-modern {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 5px;
            color: #6c757d;
        }
        .arrow-line {
            width: 30px;
            height: 1px;
            background: #6c757d;
        }
        .arrow-icon-modern {
            font-size: 1.5em;
            color: #007bff;
        }
        .alignment-text-modern {
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
        }
        .alignment-status-modern {
            text-align: center;
        }
        .alignment-result-modern {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 15px;
            border-radius: 8px;
            font-weight: 600;
        }
        .alignment-pass-modern {
            background: rgba(40,167,69,0.1);
            color: #155724;
            border: 2px solid rgba(40,167,69,0.3);
        }
        .alignment-fail-modern {
            background: rgba(220,53,69,0.1);
            color: #721c24;
            border: 2px solid rgba(220,53,69,0.3);
        }
        .alignment-icon-modern {
            font-size: 1.2em;
        }
        .alignment-text-container {
            text-align: left;
        }
        .alignment-label-modern {
            display: block;
            font-weight: 700;
        }
        .alignment-detail {
            display: block;
            font-size: 0.8em;
            opacity: 0.8;
        }
        .dmarc-conditions-explanation-modern {
            margin-bottom: 20px;
        }
        .conditions-container-modern {
            display: flex;
            align-items: stretch;
            gap: 20px;
        }
        .condition-ultra-modern {
            flex: 1;
            background: white;
            border: 2px solid #e9ecef;
            border-radius: 10px;
            padding: 20px;
            transition: all 0.3s ease;
        }
        .condition-success-modern {
            border-color: #28a745;
            background: rgba(40,167,69,0.02);
        }
        .condition-failure-modern {
            border-color: #dc3545;
            background: rgba(220,53,69,0.02);
        }
        .condition-main-header-modern {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 15px;
        }
        .condition-number-modern {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 50%;
            width: 35px;
            height: 35px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 1.1em;
        }
        .condition-title-section-modern {
            flex: 1;
        }
        .condition-title-main {
            font-weight: 700;
            font-size: 1.1em;
            color: #2c3e50;
            margin-bottom: 3px;
        }
        .condition-subtitle-modern {
            font-size: 0.85em;
            color: #6c757d;
        }
        .condition-main-status-modern {
            margin-left: auto;
        }
        .main-status-badge-modern {
            padding: 6px 12px;
            border-radius: 6px;
            font-weight: 700;
            font-size: 0.85em;
        }
        .status-met-modern {
            background: rgba(40,167,69,0.1);
            color: #155724;
            border: 1px solid rgba(40,167,69,0.3);
        }
        .status-not-met-modern {
            background: rgba(220,53,69,0.1);
            color: #721c24;
            border: 1px solid rgba(220,53,69,0.3);
        }
        .condition-requirements-modern {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        .requirement-item-modern {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 0.9em;
        }
        .requirement-met-modern {
            background: rgba(40,167,69,0.05);
            border-left: 3px solid #28a745;
        }
        .requirement-not-met-modern {
            background: rgba(220,53,69,0.05);
            border-left: 3px solid #dc3545;
        }
        .requirement-icon-modern {
            font-size: 1em;
        }
        .requirement-text-modern {
            flex: 1;
        }
        .or-separator-modern {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 10px;
            min-width: 50px;
        }
        .or-line {
            width: 1px;
            height: 30px;
            background: #dee2e6;
        }
        .or-text-modern {
            background: #f8f9fa;
            color: #6c757d;
            padding: 8px 12px;
            border-radius: 20px;
            font-weight: 700;
            font-size: 0.8em;
            border: 2px solid #dee2e6;
        }
        .final-result-ultra-modern {
            text-align: center;
        }
        .final-result-content-modern {
            background: white;
            border: 3px solid #e9ecef;
            border-radius: 15px;
            padding: 30px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }
        .final-success-modern {
            border-color: #28a745;
            background: linear-gradient(135deg, rgba(40,167,69,0.05) 0%, rgba(32,201,151,0.05) 100%);
        }
        .final-failure-modern {
            border-color: #dc3545;
            background: linear-gradient(135deg, rgba(220,53,69,0.05) 0%, rgba(200,35,51,0.05) 100%);
        }
        .final-result-icon-modern {
            font-size: 4em;
            margin-bottom: 15px;
            display: block;
        }
        .final-result-title-modern {
            font-size: 1.8em;
            font-weight: 800;
            margin-bottom: 15px;
            color: #2c3e50;
        }
        .final-result-explanation-modern {
            font-size: 1.1em;
            color: #495057;
            line-height: 1.6;
            margin-bottom: 20px;
        }
        .final-result-actions {
            margin-top: 20px;
        }
        .action-recommendation {
            background: rgba(0,123,255,0.1);
            border: 1px solid rgba(0,123,255,0.3);
            border-radius: 8px;
            padding: 12px 20px;
            font-weight: 600;
            color: #0056b3;
        }

        /* Mobile Responsive for Modern Design */
        @media (max-width: 768px) {
            .protocol-results-grid-modern {
                grid-template-columns: 1fr;
            }
            .domain-pair-modern {
                grid-template-columns: 1fr;
                gap: 15px;
                text-align: center;
            }
            .alignment-arrow-modern {
                transform: rotate(90deg);
            }
            .conditions-container-modern {
                flex-direction: column;
                gap: 15px;
            }
            .or-separator-modern {
                flex-direction: row;
                min-width: auto;
                margin: 10px 0;
            }
            .or-line {
                width: 30px;
                height: 1px;
            }
            .step-header-modern {
                padding: 15px 20px 10px;
            }
            .step-body {
                padding: 15px 20px 20px;
            }
        }

        /* Donut Chart Styles */
        .charts-section {
            background: white;
            border-radius: 12px;
            padding: 25px;
            margin: 25px 0;
            box-shadow: 0 3px 15px rgba(0,0,0,0.1);
        }
        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 30px;
            margin-top: 25px;
        }
        .chart-container {
            text-align: center;
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 8px 25px rgba(0,0,0,0.1);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        .chart-container:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(0,0,0,0.15);
        }
        .chart-container.enhanced-chart {
            border-top: 4px solid transparent;
        }
        .chart-container[data-protocol="SPF"] {
            border-top-color: #28a745;
        }
        .chart-container[data-protocol="DMARC"] {
            border-top-color: #007bff;
        }
        .chart-container[data-protocol="DKIM"] {
            border-top-color: #b007ff;
        }
        .chart-header {
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 20px;
            gap: 15px;
        }
        .protocol-icon {
            font-size: 13px;
            animation: pulse 2s infinite;
            display: flex;
            align-items: center;
            justify-content: center;
            width: 80px;
            height: 48px;
            border-radius: 12px;
            color: white;
            font-weight: bold;
            text-align: center;
        }
        .protocol-icon.spf-icon {
            background: linear-gradient(135deg, #28a745, #20c997);
        }
        .protocol-icon.dmarc-icon {
            background: linear-gradient(135deg, #007bff, #6610f2);
        }
        .protocol-icon.dkim-icon {
            background: linear-gradient(135deg, #b007ff, #e83e8c);
        }
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.1); }
            100% { transform: scale(1); }
        }
        .status-icon {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 16px;
            height: 16px;
            border-radius: 50%;
            font-size: 10px;
            font-weight: bold;
            color: white;
        }
        .status-icon.pass {
            background: #28a745;
        }
        .status-icon.fail {
            background: #dc3545;
        }
        .chart-icon {
            display: inline-block;
            font-size: 20px;
            margin-right: 8px;
        }
        .chart-title-section {
            text-align: left;
        }
        .chart-title {
            font-size: 20px;
            font-weight: 700;
            color: #2c3e50;
            margin-bottom: 2px;
        }
        .chart-subtitle {
            font-size: 12px;
            color: #6c757d;
            font-weight: 500;
        }
        .donut-chart-container {
            position: relative;
            width: 180px;
            height: 180px;
            margin: 0 auto 20px;
        }
        .interactive-donut {
            width: 100%;
            height: 100%;
            transform: rotate(-90deg);
            transition: transform 0.3s ease;
        }
        .interactive-donut:hover {
            transform: rotate(-90deg) scale(1.05);
        }
        .chart-segment {
            transition: all 0.3s ease;
            filter: drop-shadow(0 2px 4px rgba(0,0,0,0.1));
        }
        .chart-segment:hover {
            stroke-width: 5;
            filter: drop-shadow(0 4px 8px rgba(0,0,0,0.2));
        }
        .percentage-display {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
        }
        .percentage-number {
            font-size: 24px;
            font-weight: bold;
            color: #2c3e50;
            line-height: 1;
        }
        .percentage-label {
            font-size: 11px;
            color: #6c757d;
            font-weight: 500;
            margin-top: 2px;
        }
        .enhanced-legend {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 10px;
            margin-top: 20px;
            font-size: 12px;
        }
        .legend-item {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px;
            border-radius: 6px;
            transition: all 0.2s ease;
            cursor: pointer;
        }
        .legend-item:hover {
            background: #f8f9fa;
            transform: translateX(3px);
        }
        .legend-item.legend-passed {
            border-left: 3px solid #28a745;
        }
        .legend-item.legend-failed {
            border-left: 3px solid #dc3545;
        }
        .legend-icon {
            font-size: 14px;
            flex-shrink: 0;
        }
        .legend-text {
            line-height: 1.2;
            font-weight: 500;
        }
        .protocol-summary-bar {
            display: flex;
            justify-content: space-around;
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 25px;
            border: 1px solid #dee2e6;
        }
        .summary-item {
            text-align: center;
        }
        .summary-label {
            display: block;
            font-size: 12px;
            color: #6c757d;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .summary-value {
            display: block;
            font-size: 24px;
            font-weight: bold;
            color: #2c3e50;
            margin-top: 5px;
        }
        .summary-value.passed-count {
            color: #28a745;
        }
        .summary-value.failed-count {
            color: #dc3545;
        }
        .summary-value.overall-score {
            color: #007bff;
        }
        .protocol-details-toggle {
            margin-top: 15px;
            padding: 8px 15px;
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 20px;
            cursor: pointer;
            transition: all 0.2s ease;
            font-size: 12px;
            font-weight: bold;
            text-align: center;
            user-select: none;
        }
        .protocol-details-toggle:hover {
            background: #e9ecef;
            border-color: #adb5bd;
            transform: translateY(-1px);
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .protocol-details-toggle:active {
            transform: translateY(0);
        }
        .toggle-arrow {
            transition: transform 0.2s ease;
        }
        .protocol-details-toggle.expanded .toggle-arrow {
            transform: rotate(180deg);
        }
        .protocol-details {
            margin-top: 15px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            animation: slideDown 0.3s ease;
            border: 1px solid #e9ecef;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            width: 100%;
            max-width: 100%;
            box-sizing: border-box;
            overflow: hidden;
        }
        @keyframes slideDown {
            from { opacity: 0; max-height: 0; }
            to { opacity: 1; max-height: 300px; }
        }
        .detail-item {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            padding: 5px 0;
            border-bottom: 1px solid #dee2e6;
            flex-wrap: wrap;
            width: 100%;
            max-width: 100%;
            box-sizing: border-box;
        }
        .detail-item:last-child {
            border-bottom: none;
        }
        .detail-item[style*="flex-direction: column"] {
            align-items: flex-start;
            width: 100%;
        }
        .detail-label {
            font-size: 12px;
            font-weight: bold;
        }
        .detail-value {
            font-size: 14px;
            color: #5a3899;
            font-weight: bold;
        }
        .record-value-container {
            display: flex;
            flex-direction: column;
            gap: 8px;
            margin-top: 10px;
            padding: 10px;
            background: #ffffff;
            border: 1px solid #dee2e6;
            border-radius: 6px;
            width: 100%;
            max-width: 100%;
            box-sizing: border-box;
        }
        .record-value-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 8px;
        }
        .record-value-text {
            font-family: 'Courier New', monospace;
            font-size: 12px;
            word-break: break-all;
            word-wrap: break-word;
            overflow-wrap: break-word;
            line-height: 1.6;
            max-height: 200px;
            overflow-y: auto;
            padding: 8px;
            background: #f8f9fa;
            border-radius: 4px;
            width: 100%;
            max-width: 100%;
            box-sizing: border-box;
            text-align: left;
        }
        .copy-button {
            background: #007bff;
            color: white;
            border: none;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 10px;
            cursor: pointer;
            transition: all 0.2s ease;
            min-width: 60px;
        }
        .copy-button:hover {
            background: #0056b3;
            transform: translateY(-1px);
        }
        .copy-button:active {
            transform: translateY(0);
        }
        .copy-button.copied {
            background: #28a745;
        }
        .chart-tooltip {
            position: fixed;
            background: #2c3e50;
            color: white;
            padding: 12px 16px;
            border-radius: 8px;
            font-size: 12px;
            z-index: 1000;
            pointer-events: none;
            opacity: 0;
            transition: all 0.2s ease;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            max-width: 250px;
        }
        .chart-tooltip.visible {
            opacity: 1;
        }
        .tooltip-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
            padding-bottom: 8px;
            border-bottom: 1px solid rgba(255,255,255,0.2);
        }
        .tooltip-protocol {
            font-weight: bold;
            font-size: 13px;
        }
        .tooltip-status {
            font-size: 11px;
            padding: 2px 6px;
            border-radius: 4px;
            background: rgba(255,255,255,0.2);
        }
        .tooltip-check {
            font-weight: 600;
            margin-bottom: 4px;
        }
        .tooltip-description {
            font-size: 11px;
            opacity: 0.9;
            line-height: 1.3;
        }
        .protocol-comparison {
            margin-top: 30px;
            padding: 25px;
            background: white;
            border-radius: 15px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        .protocol-comparison h4 {
            margin: 0 0 20px 0;
            color: #2c3e50;
            font-weight: 600;
            text-align: center;
        }
        .comparison-bars {
            display: grid;
            gap: 15px;
        }
        .comparison-item {
            display: grid;
            grid-template-columns: 60px 1fr 50px;
            align-items: center;
            gap: 15px;
        }
        .comparison-label {
            font-weight: 600;
            color: #2c3e50;
            font-size: 14px;
        }
        .comparison-bar {
            height: 25px;
            background: #e9ecef;
            border-radius: 12px;
            overflow: hidden;
            position: relative;
        }
        .comparison-fill {
            height: 100%;
            border-radius: 12px;
            transition: width 1.5s ease;
            position: relative;
            background: linear-gradient(90deg, transparent 0%, rgba(255,255,255,0.3) 50%, transparent 100%);
            background-size: 200% 100%;
            animation: shimmer 2s infinite;
        }
        @keyframes shimmer {
            0% { background-position: -200% 0; }
            100% { background-position: 200% 0; }
        }
        .comparison-fill.spf-fill {
            background: linear-gradient(90deg, #28a745, #20c997);
        }
        .comparison-fill.dmarc-fill {
            background: linear-gradient(90deg, #007bff, #6610f2);
        }
        .comparison-fill.dkim-fill {
            background: linear-gradient(90deg, #b007ff, #e83e8c);
        }
        .comparison-value {
            font-weight: bold;
            color: #2c3e50;
            text-align: right;
            font-size: 14px;
        }
        .recommendations {
            background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%);
            border: 1px solid #ffeaa7;
            border-radius: 10px;
            padding: 20px;
            margin-top: 20px;
            border-left: 3px solid #ab7517;
        }
        .recommendations h4 {
            margin-top: 0;
            color: #856404;
        }
        .recommendations ul {
            margin-bottom: 0;
        }
        .recommendations li {
            margin-bottom: 12px;
            color: #856404;
            line-height: 1.5;
        }
        .recommendations a {
            color: #0066cc;
            text-decoration: none;
            font-weight: 500;
        }
        .recommendations a:hover {
            text-decoration: underline;
        }
        .microsoft-resources {
            background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%);
            border: 1px solid #bbdefb;
            border-radius: 10px;
            padding: 20px;
            margin-top: 20px;
        }
        .microsoft-resources h4 {
            margin-top: 0;
            color: #1565c0;
        }
        .microsoft-resources ul {
            margin-bottom: 0;
        }
        .microsoft-resources li {
            margin-bottom: 8px;
            color: #1976d2;
        }
        .microsoft-resources a {
            color: #0d47a1;
            text-decoration: none;
            font-weight: 500;
        }
        .microsoft-resources a:hover {
            text-decoration: underline;
        }
        .score-badge {
            display: inline-block;
            background: linear-gradient(135deg, #007bff 0%, #0056b3 100%);
            color: white;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 1.1em;
        }
        .progress-bar {
            width: 100%;
            height: 25px;
            background-color: #e9ecef;
            border-radius: 12px;
            overflow: hidden;
            margin: 10px 0;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #28a745 0%, #20c997 100%);
            border-radius: 12px;
            transition: width 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
        }
        .record-details {
            border-radius: 6px;
            padding: 10px;
            margin-top: 10px;
            word-break: break-all;
            border-left: 3px solid #007bff;
        }
        .icon {
            font-size: 1.2em;
            margin-right: 8px;
        }
        .footer {
            background: white;
            border-radius: 12px;
            padding: 25px;
            margin-top: 30px;
            box-shadow: 0 3px 15px rgba(0,0,0,0.1);
            text-align: center;
        }
        .legend {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        .legend-item {
            text-align: center;
            padding: 10px;
        }

        @media (max-width: 768px) {
            .domain-header {
                flex-direction: column;
                align-items: flex-start;
            }

            .summary-cards {
                grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            }
        }
    </style>
    <script>
        // Protocol Details Toggle Functionality
        function toggleProtocolDetails(detailsId) {
            const details = document.getElementById(detailsId);
            const toggle = details.previousElementSibling;
            const arrow = toggle.querySelector('.toggle-arrow');

            if (details.style.display === 'none' || details.style.display === '') {
                details.style.display = 'block';
                arrow.innerHTML = '&uarr;';
                toggle.classList.add('expanded');

                // Smooth scroll to the details section
                setTimeout(() => {
                    details.scrollIntoView({
                        behavior: 'smooth',
                        block: 'nearest',
                        inline: 'nearest'
                    });
                }, 100);
            } else {
                details.style.display = 'none';
                arrow.innerHTML = '&darr;';
                toggle.classList.remove('expanded');
            }
        }

        // Interactive Chart Functionality
        function highlightSegment(segmentId, checkName, status, protocol) {
            const segment = document.getElementById(segmentId);
            const tooltip = document.getElementById('chart-tooltip');

            // Highlight the segment
            segment.style.strokeWidth = '6';
            segment.style.filter = 'drop-shadow(0 4px 12px rgba(0,0,0,0.3))';

            // Show tooltip
            const protocolElement = tooltip.querySelector('.tooltip-protocol');
            const statusElement = tooltip.querySelector('.tooltip-status');
            const checkElement = tooltip.querySelector('.tooltip-check');
            const descriptionElement = tooltip.querySelector('.tooltip-description');

            protocolElement.textContent = protocol;
            statusElement.textContent = status;
            statusElement.style.backgroundColor = status === 'PASS' ? '#28a745' : '#dc3545';
            checkElement.textContent = checkName;

            // Add descriptions for different checks
            const descriptions = {
                'Record Present': 'Checks if the DNS record exists for this domain',
                'Single Record': 'Ensures only one SPF record exists (RFC requirement)',
                'Macro Security': 'Validates safe usage of SPF macros',
                'TTL Sub-Records': 'Verifies TTL values for A/MX/TXT records referenced in SPF (includes A, MX, and include mechanisms)',
                'DNS Lookups < 10': 'SPF records must not exceed 10 DNS lookups',
                'Record Length < 255': 'DNS TXT records have a 255 character limit',
                'TTL >= 3600': 'Minimum recommended TTL for DNS stability',
                'Strict All Mechanism': 'Uses ~all or -all for proper email protection',
                'Syntax Valid': 'Record follows correct syntax standards',
                'Reporting Configured': 'RUA/RUF tags configured for DMARC reporting',
                'Strong Policy (reject only)': 'Only reject policy provides maximum security - quarantine is considered weak',
                'Keys Active': 'DKIM keys are active and not revoked',
                'Strong Keys': 'Key lengths meet security standards (1024+ bits)',
                'Subdomain Policy': 'Explicit DKIM policy configuration for subdomains',
                'Key Age Tracking': 'DKIM key expiration and rotation tracking available',
                'Canonicalization': 'Optimal DKIM canonicalization methods configured'
            };

            descriptionElement.textContent = descriptions[checkName] || 'Security check validation';

            // Position tooltip
            tooltip.style.left = event.pageX + 10 + 'px';
            tooltip.style.top = event.pageY - 10 + 'px';
            tooltip.classList.add('visible');
        }

        function resetSegment(segmentId) {
            const segment = document.getElementById(segmentId);
            const tooltip = document.getElementById('chart-tooltip');

            // Reset segment styling
            segment.style.strokeWidth = '4';
            segment.style.filter = 'drop-shadow(0 2px 4px rgba(0,0,0,0.1))';

            // Hide tooltip
            tooltip.classList.remove('visible');
        }

        // Copy to clipboard functionality
        function copyToClipboard(text, buttonId) {
            navigator.clipboard.writeText(text).then(function() {
                const button = document.getElementById(buttonId);
                const originalText = button.textContent;
                button.textContent = 'Copied!';
                button.classList.add('copied');

                setTimeout(function() {
                    button.textContent = originalText;
                    button.classList.remove('copied');
                }, 2000);
            }).catch(function(err) {
                // Fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = text;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);

                const button = document.getElementById(buttonId);
                const originalText = button.textContent;
                button.textContent = 'Copied!';
                button.classList.add('copied');

                setTimeout(function() {
                    button.textContent = originalText;
                    button.classList.remove('copied');
                }, 2000);
            });
        }

        // Calculate and update summary counts
        function updateSummaryCounts() {
            const domains = document.querySelectorAll('.domain-section');
            domains.forEach((domain, index) => {
                const passedElements = domain.querySelectorAll('.legend-item.legend-passed');
                const failedElements = domain.querySelectorAll('.legend-item.legend-failed');

                const passedCount = passedElements.length;
                const failedCount = failedElements.length;

                // Find the passed/failed count elements in this domain
                const passedCountElement = domain.querySelector('.passed-count');
                const failedCountElement = domain.querySelector('.failed-count');

                if (passedCountElement) passedCountElement.textContent = passedCount;
                if (failedCountElement) failedCountElement.textContent = failedCount;
            });
        }

        // Initialize interactive features
        document.addEventListener('DOMContentLoaded', function() {
            // Initialize interactive features
            updateSummaryCounts();

            // Add hover effects to legend items
            const legendItems = document.querySelectorAll('.legend-item');
            legendItems.forEach(item => {
                item.addEventListener('mouseenter', function() {
                    const checkName = this.getAttribute('data-check');
                    const protocol = this.getAttribute('data-protocol');

                    // Find corresponding chart segment
                    const chartContainer = this.closest('.chart-container');
                    const segments = chartContainer.querySelectorAll('.chart-segment');
                    segments.forEach(segment => {
                        if (segment.getAttribute('data-check') === checkName) {
                            segment.style.strokeWidth = '6';
                            segment.style.filter = 'drop-shadow(0 4px 12px rgba(0,0,0,0.3))';
                        }
                    });
                });

                item.addEventListener('mouseleave', function() {
                    const checkName = this.getAttribute('data-check');
                    const chartContainer = this.closest('.chart-container');
                    const segments = chartContainer.querySelectorAll('.chart-segment');
                    segments.forEach(segment => {
                        if (segment.getAttribute('data-check') === checkName) {
                            segment.style.strokeWidth = '4';
                            segment.style.filter = 'drop-shadow(0 2px 4px rgba(0,0,0,0.1))';
                        }
                    });
                });
            });
        });
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><span class="chart-icon">&#9993;</span>Email Authentication Report</h1>
            <p>Analyzing SPF, DKIM, and DMARC records</p>
            <p>Generated on $reportDate at $(Get-Date -Format "HH:mm:ss")</p>
        </div>

        <div class="summary-section">
            <h2 class="summary-title">Analysis Summary</h2>
            <div class="summary-cards">
                <div class="summary-card">
                    <h3>Total Domains</h3>
                    <div class="number">$totalDomains</div>
                    <div class="label">Analyzed</div>
                </div>
                <div class="summary-card">
                    <h3>Average Score</h3>
                    <div class="number">$avgScore</div>
                    <div class="label">Out of 100</div>
                </div>

            </div>
        </div>

        <div class="content">
"@

# Add domain sections
$domainIndex = 0
foreach ($result in $allResults) {
    $domainIndex++
    $domainId = ($result.Domain -replace '[^a-zA-Z0-9]', '') + $domainIndex  # Create safe ID from domain name + index

    $statusClass = switch ($result.Status) {
        "Excellent" { "status-excellent" }
        "Good" { "status-good" }
        "Fair" { "status-fair" }
        "Poor" { "status-poor" }
        "Critical" { "status-critical" }
    }

    $progressWidth = $result.Score
    $progressText = "$($result.Score)%"

    # Set progress bar color based on score with enhanced thresholds
    $progressColor = if ($result.Score -ge 95) { "linear-gradient(90deg, #28a745 0%, #20c997 100%)" }  # Excellent (95+)
    elseif ($result.Score -ge 85) { "linear-gradient(90deg, #17a2b8 0%, #138496 100%)" }  # Good (85-94)
    elseif ($result.Score -ge 65) { "linear-gradient(90deg, #ffc107 0%, #e0a800 100%)" }  # Fair (65-84)
    elseif ($result.Score -ge 40) { "linear-gradient(90deg, #fd7e14 0%, #e55353 100%)" }  # Poor (40-64)
    else { "linear-gradient(90deg, #dc3545 0%, #b02a37 100%)" }  # Critical (<40)

    $html += @"
    <div class="domain-section">
        <div class="domain-header">
            <h2 class="domain-name"><span class="chart-icon">&#127760;</span>$($result.Domain)</h2>
            <div class="score-section">
                <span class="score-badge">Score: $($result.Score)/100</span>
                <span class="$statusClass">$($result.Status)</span>
            </div>
        </div>

        <div class="progress-bar">
            <div class="progress-fill" style="width: $progressWidth%; background: $progressColor;">$progressText</div>
        </div>

        <div class="charts-section">
            <h3><span class="chart-icon">&#128202;</span>Protocol Health Overview</h3>
            <div class="protocol-summary-bar">
                <div class="summary-item">
                    <span class="summary-label">Total Checks:</span>
                    <span class="summary-value">19</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Passed:</span>
                    <span class="summary-value passed-count" id="passed-count-$domainId">0</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Failed:</span>
                    <span class="summary-value failed-count" id="failed-count-$domainId">0</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Overall:</span>
                    <span class="summary-value overall-score">$($result.Score)%</span>
                </div>
            </div>

            <div class="charts-grid">
                <div class="chart-container enhanced-chart" data-protocol="SPF">
                    <div class="chart-header">
                        <div class="protocol-icon spf-icon">SPF</div>
                        <div class="chart-title-section">
                            <div class="chart-title">SPF Protection</div>
                            <div class="chart-subtitle">Sender Policy Framework</div>
                        </div>
                    </div>
                    <div class="donut-chart-container">
$(Add-SegmentedDonutChart (Get-ProtocolCheckDetails $result "SPF") "SPF")
                    </div>
                    <div class="chart-status $(if($result.SPFCheckPercentage -ge 90){'excellent'}elseif($result.SPFCheckPercentage -ge 70){'good'}elseif($result.SPFCheckPercentage -ge 50){'fair'}else{'poor'})">
                        $(if($result.SPFFound){"$($result.SPFCheckPercentage)% Compliant"}else{"Not Configured"})
                    </div>
                    <div class="segment-legend enhanced-legend" id="spf-legend-$domainId">
$((Get-ProtocolCheckDetails $result "SPF") | ForEach-Object {
    $statusIcon = if($_.Passed) { "<span class='status-icon pass'>&check;</span>" } else { "<span class='status-icon fail'>&times;</span>" }
    $statusClass = if($_.Passed) { "legend-passed" } else { "legend-failed" }
    "<div class='legend-item $statusClass' data-check='$($_.Name)' data-protocol='SPF'><div class='legend-icon'>$statusIcon</div><div class='legend-text'>$($_.Name)</div></div>"
} | Out-String)
                    </div>
                    <div class="protocol-details-toggle" onclick="toggleProtocolDetails('spf-details-$domainId')">
                        <span>View Details</span> <span class="toggle-arrow">&darr;</span>
                    </div>
                    <div class="protocol-details" id="spf-details-$domainId" style="display: none;">
                        <div class="detail-item">
                            <span class="detail-label">Record Length:</span>
                            <span class="detail-value">$($result.SPFRecordLength) chars</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">DNS Lookups:</span>
                            <span class="detail-value">$($result.SpfDnsLookups)/10</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">TTL:</span>
                            <span class="detail-value">$($result.SpfTTL) seconds</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Single Record:</span>
                            <span class="detail-value">$(if(-not $result.SPFFound) { 'Missing record' } elseif($result.SPFMultipleRecordsCheck) { 'Yes' } else { 'Multiple records found' })</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Macro Security:</span>
                            <span class="detail-value">$(if(-not $result.SPFFound) { 'Missing' } elseif($result.SPFMacroSecurityCheck) { 'Safe Macro Usage' } else { 'Review Macro Security' })</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">TTL Sub-Records:</span>
                            <span class="detail-value">$(if(-not $result.SPFFound) { 'Missing' } elseif($result.SPFSubRecordsTTLCheck) { 'A/MX records TTL &ge;3600s' } else { 'Low TTL on A/MX records' })</span>
                        </div>
$(if($result.SPFSubRecordsTTLValues -and $result.SPFSubRecordsTTLValues.Count -gt 0) {
"                        <div class='detail-item' style='flex-direction: column; align-items: flex-start;'>
                            <span class='detail-label'>Sub-Record TTL Details:</span>
                            <div class='record-value-container'>
                                <div class='record-value-header'>
                                    <span style='font-size: 11px; color: #6c757d;'>A/MX/TXT record TTL values referenced in SPF</span>
                                </div>
                                <div class='record-value-text'>
                                    <table style='width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 0.85em; table-layout: fixed;'>
                                        <colgroup>
                                            <col style='width: 30%;'>
                                            <col style='width: 55%;'>
                                            <col style='width: 15%;'>
                                        </colgroup>
                                        <thead>
                                            <tr style='background-color: #f8f9fa; border-bottom: 2px solid #dee2e6;'>
                                                <th style='padding: 8px 12px; text-align: left; font-weight: 600; color: #495057; border: 1px solid #dee2e6;'>Record Name</th>
                                                <th style='padding: 8px 12px; text-align: left; font-weight: 600; color: #495057; border: 1px solid #dee2e6;'>Value</th>
                                                <th style='padding: 8px 12px; text-align: left; font-weight: 600; color: #495057; border: 1px solid #dee2e6;'>TTL</th>
                                            </tr>
                                        </thead>
                                        <tbody>
$(
    $tableRows = @()
    foreach($kvp in $result.SPFSubRecordsTTLValues.GetEnumerator()) {
        $recordName = $kvp.Key
        $recordData = $kvp.Value

        # Parse the record data - it can contain multiple entries separated by commas
        $entries = $recordData -split ', '

        foreach($entry in $entries) {
            # Extract value and TTL from each entry
            if($entry -match '^(.+?):\s*(\d+s?)$') {
                $recordValue = $matches[1].Trim()
                $ttlValue = $matches[2].Trim()

                # Determine row background color based on TTL value
                $ttlNumeric = ($ttlValue -replace 's', '') -as [int]
                $rowStyle = if($ttlNumeric -lt 3600) {
                    'background-color: #fff3cd; border: 1px solid #ffeaa7;'
                } else {
                    'background-color: #ffffff; border: 1px solid #dee2e6;'
                }

                $tableRows += "                                            <tr style='$rowStyle'>
                                                <td style='padding: 6px 12px; border: 1px solid #dee2e6; word-wrap: break-word; overflow-wrap: break-word;'><strong>$recordName</strong></td>
                                                <td style='padding: 6px 12px; border: 1px solid #dee2e6; word-wrap: break-word; overflow-wrap: break-word; font-family: monospace; font-size: 0.9em; white-space: pre-wrap;'>$recordValue</td>
                                                <td style='padding: 6px 12px; border: 1px solid #dee2e6; text-align: center; font-weight: 500; white-space: nowrap;'>$ttlValue</td>
                                            </tr>"
            } else {
                # Handle cases where the format doesn't match expected pattern
                $tableRows += "                                            <tr style='background-color: #f8d7da; border: 1px solid #f5c6cb;'>
                                                <td style='padding: 6px 12px; border: 1px solid #dee2e6; word-wrap: break-word; overflow-wrap: break-word;'><strong>$recordName</strong></td>
                                                <td style='padding: 6px 12px; border: 1px solid #dee2e6; word-wrap: break-word; overflow-wrap: break-word; font-family: monospace; font-size: 0.9em; white-space: pre-wrap;'>$entry</td>
                                                <td style='padding: 6px 12px; border: 1px solid #dee2e6; text-align: center; color: #721c24; white-space: nowrap;'>N/A</td>
                                            </tr>"
            }
        }
    }
    $tableRows -join "`n"
)
                                        </tbody>
                                    </table>
                                    <div style='margin-top: 8px; font-size: 0.75em; color: #6c757d;'>
                                        <span style='display: inline-block; width: 12px; height: 12px; background-color: #fff3cd; border: 1px solid #ffeaa7; margin-right: 5px;'></span>Yellow background indicates TTL &lt; 3600 seconds
                                    </div>
                                </div>
                            </div>
                        </div>"
})
                        <div class="detail-item">
                            <span class="detail-label">SPF Enforcement Rule:</span>
                            <span class="detail-value">$(
                                if(-not $result.SPFFound) {
                                    'Missing'
                                } else {
                                    switch ($result.SPFAllMechanism) {
                                        '?all' { '?all (WEAK - Neutral: Pass or fail, no specific action on messages from unidentified senders)' }
                                        '~all' { '~all (GOOD - Soft Fail: Emails not from unauthorized senders will be accepted but marked [depends on the destination email system])' }
                                        '-all' { '-all (STRICT - Hard Fail: Emails from authorized senders will be accepted only)'}
                                        'Missing' { 'Missing' }
                                        '' { 'MISSING (incomplete policy)' }
                                        default { $result.SPFAllMechanism }
                                    }
                                }
                            )</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Syntax:</span>
                            <span class="detail-value">$(if($result.SPFSyntaxValid) { 'Valid' } else { 'Invalid' })</span>
                        </div>
                        <div class="detail-item" style="flex-direction: column; align-items: flex-start;">
                            <span class="detail-label">SPF Record:</span>
                            <div class="record-value-container">
                                <div class="record-value-header">
                                    <span style="font-size: 11px;">Click to copy record value</span>
                                    <button class="copy-button" id="copy-spf-$domainId" onclick="copyToClipboard('$(if($result.SPFRecord) { $result.SPFRecord -replace "'", "\'" } else { "No SPF record found" })', 'copy-spf-$domainId')">Copy</button>
                                </div>
                                <div class="record-value-text">$(if($result.SPFRecord) { $result.SPFRecord } else { "No SPF record found" })</div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="chart-container enhanced-chart" data-protocol="DMARC">
                    <div class="chart-header">
                        <div class="protocol-icon dmarc-icon">DMARC</div>
                        <div class="chart-title-section">
                            <div class="chart-title">DMARC Policy</div>
                            <div class="chart-subtitle">Domain-based Message Authentication</div>
                        </div>
                    </div>
                    <div class="donut-chart-container">
$(Add-SegmentedDonutChart (Get-ProtocolCheckDetails $result "DMARC") "DMARC")
                    </div>
                    <div class="chart-status $(if($result.DMARCCheckPercentage -ge 90){'excellent'}elseif($result.DMARCCheckPercentage -ge 70){'good'}elseif($result.DMARCCheckPercentage -ge 50){'fair'}else{'poor'})">
                        $(if($result.DMARCFound){"$($result.DMARCCheckPercentage)% Compliant"}else{"Not Configured"})
                    </div>
                    <div class="segment-legend enhanced-legend" id="dmarc-legend-$domainId">
$((Get-ProtocolCheckDetails $result "DMARC") | ForEach-Object {
    $statusIcon = if($_.Passed) { "<span class='status-icon pass'>&check;</span>" } else { "<span class='status-icon fail'>&times;</span>" }
    $statusClass = if($_.Passed) { "legend-passed" } else { "legend-failed" }
    "<div class='legend-item $statusClass' data-check='$($_.Name)' data-protocol='DMARC'><div class='legend-icon'>$statusIcon</div><div class='legend-text'>$($_.Name)</div></div>"
} | Out-String)
                    </div>
                    <div class="protocol-details-toggle" onclick="toggleProtocolDetails('dmarc-details-$domainId')">
                        <span>View Details</span> <span class="toggle-arrow">&darr;</span>
                    </div>
                    <div class="protocol-details" id="dmarc-details-$domainId" style="display: none;">
                        <div class="detail-item">
                            <span class="detail-label">Policy:</span>
                            <span class="detail-value">$(if($result.DMARCPolicy) { (Get-Culture).TextInfo.ToTitleCase($result.DMARCPolicy.ToLower()) } else { $result.DMARCPolicy })</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Subdomain Policy:</span>
                            <span class="detail-value">$(if($result.DMARCSubdomainPolicy -eq $result.DMARCPolicy) { "$(if($result.DMARCSubdomainPolicy) { (Get-Culture).TextInfo.ToTitleCase($result.DMARCSubdomainPolicy.ToLower()) } else { $result.DMARCSubdomainPolicy }) (inherited)" } else { if($result.DMARCSubdomainPolicy) { (Get-Culture).TextInfo.ToTitleCase($result.DMARCSubdomainPolicy.ToLower()) } else { $result.DMARCSubdomainPolicy } })</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">SPF Alignment:</span>
                            <span class="detail-value">$(if($result.DmarcSPFAlignment -eq 'r') { 'Relaxed (r)' } elseif($result.DmarcSPFAlignment -eq 's') { 'Strict (s)' } else { $result.DmarcSPFAlignment })</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">DKIM Alignment:</span>
                            <span class="detail-value">$(if($result.DmarcDKIMAlignment -eq 'r') { 'Relaxed (r)' } elseif($result.DmarcDKIMAlignment -eq 's') { 'Strict (s)' } else { $result.DmarcDKIMAlignment })</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Failure Options:</span>
                            <span class="detail-value">$(
                                switch ($result.DMARCFailureOptions) {
                                    '0' { '0 (Default: Generate report only if both SPF and DKIM fail to align)' }
                                    '1' { '1 (Generate report if either SPF or DKIM fails to align)' }
                                    'd' { 'd (Generate report if DKIM fails to align, regardless of SPF)' }
                                    's' { 's (Generate report if SPF fails to align, regardless of DKIM)' }
                                    'Missing' { 'Missing' }
                                    default { $result.DMARCFailureOptions }
                                }
                            )</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Reporting:</span>
                            <span class="detail-value">$(if($result.DMARCRecord -match 'rua=') { 'Configured' } else { 'Not Configured' })</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Record Found:</span>
                            <span class="detail-value">$(if($result.DMARCFound) { 'Yes' } else { 'No' })</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">TTL:</span>
                            <span class="detail-value">$(if($result.DmarcTTL -gt 0) { "$($result.DmarcTTL)s" } else { 'Not Available' })</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Protocol Version:</span>
                            <span class="detail-value">$(if($result.DMARCVersion -ne 'Missing') { $result.DMARCVersion } else { 'Not Available' })</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Percentage of messages subjected to filtering:</span>
                            <span class="detail-value">$(if($result.DMARCPercentage -ne 'Missing') { "$($result.DMARCPercentage)%" } else { 'Not Available' })</span>
                        </div>
                        <div class="detail-item" style="flex-direction: column; align-items: flex-start;">
                            <span class="detail-label">DMARC Record:</span>
                            <div class="record-value-container">
                                <div class="record-value-header">
                                    <span style="font-size: 11px; color: #6c757d;">Click to copy record value</span>
                                    <button class="copy-button" id="copy-dmarc-$domainId" onclick="copyToClipboard('$(if($result.DMARCRecord) { $result.DMARCRecord -replace "'", "\'" } else { "No DMARC record found" })', 'copy-dmarc-$domainId')">Copy</button>
                                </div>
                                <div class="record-value-text">$(if($result.DMARCRecord) { $result.DMARCRecord } else { "No DMARC record found" })</div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="chart-container enhanced-chart" data-protocol="DKIM">
                    <div class="chart-header">
                        <div class="protocol-icon dkim-icon">DKIM</div>
                        <div class="chart-title-section">
                            <div class="chart-title">DKIM Signatures</div>
                            <div class="chart-subtitle">DomainKeys Identified Mail</div>
                        </div>
                    </div>
                    <div class="donut-chart-container">
$(Add-SegmentedDonutChart (Get-ProtocolCheckDetails $result "DKIM") "DKIM")
                    </div>
                    <div class="chart-status $(if($result.DKIMCheckPercentage -ge 90){'excellent'}elseif($result.DKIMCheckPercentage -ge 70){'good'}elseif($result.DKIMCheckPercentage -ge 50){'fair'}else{'poor'})">
                        $(if($result.DKIMFound){"$($result.DKIMCheckPercentage)% Compliant"}else{"Not Configured"})
                    </div>
                    <div class="segment-legend enhanced-legend" id="dkim-legend-$domainId">
$((Get-ProtocolCheckDetails $result "DKIM") | ForEach-Object {
    $statusIcon = if($_.Passed) { "<span class='status-icon pass'>&check;</span>" } else { "<span class='status-icon fail'>&times;</span>" }
    $statusClass = if($_.Passed) { "legend-passed" } else { "legend-failed" }
    "<div class='legend-item $statusClass' data-check='$($_.Name)' data-protocol='DKIM'><div class='legend-icon'>$statusIcon</div><div class='legend-text'>$($_.Name)</div></div>"
} | Out-String)
                    </div>
                    <div class="protocol-details-toggle" onclick="toggleProtocolDetails('dkim-details-$domainId')">
                        <span>View Details</span> <span class="toggle-arrow">&darr;</span>
                    </div>
                    <div class="protocol-details" id="dkim-details-$domainId" style="display: none;">
                        <div class="detail-item">
                            <span class="detail-label">Selectors Found:</span>
                            <span class="detail-value">$(if($result.DKIMSelectors.Count -gt 0) { $result.DKIMSelectors.Count } else { '0' })</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Active Keys:</span>
                            <span class="detail-value">$(($result.DKIMAllMechanisms.Values | Where-Object { $_ -eq 'ACTIVE' }).Count)</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Syntax Valid:</span>
                            <span class="detail-value">$(if($result.DKIMSyntaxValid) { 'Yes' } else { 'No' })</span>
                        </div>
$(if($result.DkimTTL -and $result.DkimTTL.Count -gt 0) {
    $ttlSummary = @()
    foreach ($kvp in $result.DkimTTL.GetEnumerator()) {
        $selector = $kvp.Key
        $ttlValue = $kvp.Value
        if ($ttlValue -gt 0) {
            $ttlText = if ($ttlValue -lt 3600) { "$ttlValue s (Low)" } else { "$ttlValue s" }
            $ttlSummary += "$selector`: $ttlText"
        }
    }
    if ($ttlSummary.Count -gt 0) {
"                        <div class='detail-item'>
                            <span class='detail-label'>TTL:</span>
                            <span class='detail-value'>$($ttlSummary -join ', ')</span>
                        </div>"
    }
})
$(if($result.DKIMKeyLengths -and $result.DKIMKeyLengths.Count -gt 0) {
    $keyLengthSummary = @()
    foreach ($kvp in $result.DKIMKeyLengths.GetEnumerator()) {
        $selector = $kvp.Key
        $keyInfo = $kvp.Value
        if ($keyInfo.KeyLength -gt 0) {
            $strengthText = if ($keyInfo.IsWeak) { " (Weak)" } else { " (Strong)" }
            $keyLengthSummary += "$selector`: $($keyInfo.KeyLength) bits$strengthText"
        }
    }
    if ($keyLengthSummary.Count -gt 0) {
"                        <div class='detail-item'>
                            <span class='detail-label'>Key Lengths:</span>
                            <span class='detail-value'>$($keyLengthSummary -join ', ')</span>
                        </div>"
    }
})
$(if($result.DKIMProviders -and $result.DKIMProviders.Detected.Count -gt 0) {
"                        <div class='detail-item'>
                            <span class='detail-label'>Service Provider:</span>
                            <span class='detail-value'>$($result.DKIMProviders.Detected -join ', ')</span>
                        </div>"
})
                        <div class="detail-item" style="flex-direction: column; align-items: flex-start;">
                            <span class="detail-label">DKIM Records:</span>
                            <div class="record-value-container">
                                <div class="record-value-header">
                                    <span style="font-size: 11px; color: #6c757d;">Click to copy record values</span>
                                    <button class="copy-button" id="copy-dkim-$domainId" onclick="copyToClipboard('$(if($result.DKIMRecords.Count -gt 0) { ($result.DKIMRecords.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join "`n" -replace "'", "\'" } else { "No DKIM records found" })', 'copy-dkim-$domainId')">Copy</button>
                                </div>
                                <div class="record-value-text">$(if($result.DKIMRecords.Count -gt 0) { ($result.DKIMRecords.GetEnumerator() | ForEach-Object { "<strong>$($_.Key):</strong> $($_.Value)" }) -join "<br>" } else { "No DKIM records found" })</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Interactive Tooltip -->
            <div id="chart-tooltip" class="chart-tooltip">
                <div class="tooltip-header">
                    <span class="tooltip-protocol"></span>
                    <span class="tooltip-status"></span>
                </div>
                <div class="tooltip-content">
                    <div class="tooltip-check"></div>
                    <div class="tooltip-description"></div>
                </div>
            </div>

            <!-- MX Record Information Section -->
            <div class="mx-record-section" style="margin-top: 30px; padding: 25px; background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); border-radius: 15px; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">
                <h4 style="margin: 0 0 20px 0; color: #2c3e50; font-weight: 600; display: flex; align-items: center; gap: 10px;">
                    <span style="font-size: 1.3em;">&#128231;</span>MX Record Analysis
                </h4>

$(if($result.MXFound) {
@"
                <div class="mx-summary" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px;">
                    <div class="mx-stat-card" style="background: white; padding: 15px; border-radius: 10px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                        <div style="font-size: 1.5em; font-weight: bold; color: #28a745;">$($result.MXRecords.Count)</div>
                        <div style="font-size: 0.9em; color: #6c757d;">MX Records</div>
                    </div>
                    <div class="mx-stat-card" style="background: white; padding: 15px; border-radius: 10px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                        <div style="font-size: 1.1em; font-weight: bold; color: #007bff;">$($result.MXAverageTTL)s</div>
                        <div style="font-size: 0.9em; color: #6c757d;">TTL</div>
                    </div>
$(if($result.MXProviders.Count -gt 0) {
"                    <div class='mx-stat-card' style='background: white; padding: 15px; border-radius: 10px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.1);'>
                        <div style='font-size: 1em; font-weight: bold; color: #6f42c1;'>$($result.MXProviders -join ', ')</div>
                        <div style='font-size: 0.9em; color: #6c757d;'>Email Provider</div>
                    </div>"
})
                </div>

                <div class="mx-records-table" style="background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                    <table style="width: 100%; border-collapse: collapse;">
                        <thead style="background: linear-gradient(135deg, #007bff 0%, #0056b3 100%); color: white;">
                            <tr>
                                <th style="padding: 12px; text-align: left; font-weight: 600;">Priority</th>
                                <th style="padding: 12px; text-align: left; font-weight: 600;">Mail Server</th>
                                <th style="padding: 12px; text-align: center; font-weight: 600;">TTL (seconds)</th>
                                <th style="padding: 12px; text-align: center; font-weight: 600;">Status</th>
                            </tr>
                        </thead>
                        <tbody>
$(
    $rowCount = 0
    foreach($mxRecord in $result.MXRecords) {
        $rowCount++
        $rowStyle = if($rowCount % 2 -eq 0) { "background-color: #f8f9fa;" } else { "background-color: white;" }
        $ttlColor = if($mxRecord.TTL -lt 3600) { "color: #dc3545; font-weight: bold;" } else { "color: #28a745;" }
        $isPrimary = ($mxRecord.Server -eq $result.MXPrimaryMX)
        $statusText = if($isPrimary) { "Primary" } else { "Backup" }
        $statusColor = if($isPrimary) { "#28a745" } else { "#6c757d" }

"                            <tr style='$rowStyle border-bottom: 1px solid #dee2e6;'>
                                <td style='padding: 12px; font-weight: bold; color: #2c3e50;'>$($mxRecord.Priority)</td>
                                <td style='padding: 12px; font-family: monospace; font-size: 0.9em; color: #495057;'>$($mxRecord.Server)</td>
                                <td style='padding: 12px; text-align: center; $ttlColor'>$($mxRecord.TTL)</td>
                                <td style='padding: 12px; text-align: center;'>
                                    <span style='background: $statusColor; color: white; padding: 4px 8px; border-radius: 12px; font-size: 0.8em; font-weight: bold;'>$statusText</span>
                                </td>
                            </tr>"
    }
)
                        </tbody>
                    </table>
                </div>
"@
} else {
@"
                <div class="mx-not-found" style="text-align: center; padding: 30px; background: linear-gradient(135deg, #f8d7da 0%, #f5c6cb 100%); border: 1px solid #f5c6cb; border-radius: 10px;">
                    <div style="font-size: 3em; margin-bottom: 15px;">&#10060;</div>
                    <h5 style="color: #721c24; margin-bottom: 10px;">No MX Records Found</h5>
                    <p style="color: #721c24; margin: 0; font-size: 0.95em;">This domain does not have MX records configured, which means it cannot receive email.</p>
                </div>
"@
})
            </div>

            <div class="protocol-comparison">
                <h4>Security Level Comparison</h4>
                <div class="comparison-bars">
                    <div class="comparison-item">
                        <div class="comparison-label">SPF</div>
                        <div class="comparison-bar">
                            <div class="comparison-fill spf-fill" style="width: $($result.SPFCheckPercentage)%"></div>
                        </div>
                        <div class="comparison-value">$($result.SPFCheckPercentage)%</div>
                    </div>
                    <div class="comparison-item">
                        <div class="comparison-label">DMARC</div>
                        <div class="comparison-bar">
                            <div class="comparison-fill dmarc-fill" style="width: $($result.DMARCCheckPercentage)%"></div>
                        </div>
                        <div class="comparison-value">$($result.DMARCCheckPercentage)%</div>
                    </div>
                    <div class="comparison-item">
                        <div class="comparison-label">DKIM</div>
                        <div class="comparison-bar">
                            <div class="comparison-fill dkim-fill" style="width: $($result.DKIMCheckPercentage)%"></div>
                        </div>
                        <div class="comparison-value">$($result.DKIMCheckPercentage)%</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Domain-specific Action Items & Microsoft Documentation -->
        $(if ($result.Recommendations.Count -gt 0) {
            # Determine section title based on provider
            $sectionTitle = if ($result.MXProviders -contains "Microsoft/Office 365") {
                "Action Items &amp; Microsoft Recommendations"
            } else {
                "Action Items &amp; Recommendations From Industry Standard Resources"
            }
@"
        <div class='recommendations'>
            <h4>&#128295; $sectionTitle for $($result.Domain)</h4>
            <ul>
$(
    foreach ($recommendation in $result.Recommendations) {
        # Format recommendations with proper HTML links (both HTTP and HTTPS)
        $formattedRec = $recommendation -replace "(https?://[^\s]+)", '<a href="$1" target="_blank">$1</a>'
        "                <li>$formattedRec</li>"
    }
)
            </ul>
        </div>
"@
        })

        <!-- Domain-specific Provider Documentation -->
        $(
        $domainURLs = Get-ProviderSpecificURLs -Providers $result.MXProviders
        # Determine documentation section title based on provider
        $docTitle = if ($result.MXProviders -contains "Microsoft/Office 365") {
            "Microsoft Official Documentation"
        } else {
            "Industry Standard Documentation"
        }
@"
        <div class="microsoft-resources">
            <h4>&#128218; $docTitle for $($result.Domain)</h4>
            <p><em>Provider-specific documentation based on detected email provider: $($result.MXProviders -join ', ')</em></p>
            <ul>
                <li><strong>SPF Setup:</strong> <a href='$($domainURLs.SPFSetup)' target='_blank'>SPF Setup Guide</a></li>
                <li><strong>DKIM Setup:</strong> <a href='$($domainURLs.DKIMSetup)' target='_blank'>DKIM Setup Guide</a></li>
                <li><strong>DMARC Setup:</strong> <a href='$($domainURLs.DMARCSetup)' target='_blank'>DMARC Setup Guide</a></li>
            </ul>
        </div>
"@
        )

$(if($menuChoice -eq '4' -and ($result.EmailHeaderSPFResult -ne "" -or $result.EmailHeaderDKIMResult -ne "" -or $result.EmailHeaderDMARCResult -ne "")) {
@"
        <!-- Email Header Analysis Section - Redesigned for User Friendliness -->
        <div class="email-header-section">
            <div class="email-header-main-title">
                <span class="main-title-icon">&#128231;</span>
                <div class="main-title-content">
                    <h2>Email Authentication Analysis</h2>
                    <p class="main-title-subtitle">Understanding how this email performed against authentication protocols</p>
                </div>
            </div>

            <!-- Overall Result Banner -->
            <div class="overall-result-banner $(if($result.EmailHeaderDMARCPass -eq 'Yes'){'result-banner-pass'}elseif($result.EmailHeaderDMARCPass -eq 'No'){'result-banner-fail'}else{'result-banner-neutral'})">
                <div class="result-banner-content">
                    <div class="result-banner-icon">
                        $(if($result.EmailHeaderDMARCPass -eq 'Yes'){'&#10003;'}elseif($result.EmailHeaderDMARCPass -eq 'No'){'&#10007;'}else{'&#128269;'})
                    </div>
                    <div class="result-banner-text">
                        <div class="result-banner-main">
                            $(if($result.EmailHeaderDMARCPass -eq 'Yes'){
                                if($result.EmailHeaderCondition1Met -and $result.EmailHeaderCondition2Met) {
                                    'EXCELLENT: Email PASSED DMARC Authentication'
                                } else {
                                    'GOOD: Email PASSED DMARC Authentication'
                                }
                            } elseif($result.EmailHeaderDMARCPass -eq 'No') {
                                'FAILED: Email FAILED DMARC Authentication'
                            } else {
                                'EMAIL AUTHENTICATION ANALYSIS RESULTS'
                            })
                        </div>
                        <div class="result-banner-detail">
                            $(if($result.EmailHeaderDMARCPass -eq 'Yes'){
                                if($result.EmailHeaderCondition1Met -and $result.EmailHeaderCondition2Met) {
                                    'Both SPF and DKIM authentication methods succeeded with proper domain alignment'
                                } else {
                                    'At least one authentication method (SPF or DKIM) succeeded with proper domain alignment'
                                }
                            } elseif($result.EmailHeaderDMARCPass -eq 'No') {
                                'Neither SPF nor DKIM authentication succeeded with proper domain alignment'
                            } else {
                                'Analysis of email authentication headers from the message'
                            })
                        </div>
                    </div>
                </div>
            </div>

            <!-- Step-by-Step Authentication Flow - Redesigned for Clarity -->
            <div class="auth-flow-container-clear">
                <div class="flow-title-modern">
                    <span class="flow-icon">&#128200;</span>
                    <h3>Authentication Process Breakdown</h3>
                    <p class="flow-subtitle">Step-by-step analysis of email authentication</p>
                </div>

                <!-- Step 1: Protocol Results -->
                <div class="auth-step-clear step-1">
                    <div class="step-header-modern">
                        <div class="step-indicator">
                            <span class="step-number-modern">1</span>
                            <div class="step-connector"></div>
                        </div>
                        <div class="step-content-header">
                            <h4 class="step-title-modern">Protocol Authentication Results</h4>
                            <p class="step-description">Check if each authentication protocol passed or failed</p>
                        </div>
                    </div>
                    <div class="step-body">
                        <div class="protocol-results-grid-modern">
                            <div class="protocol-card-modern spf-card">
                                <div class="protocol-header-modern">
                                    <div class="protocol-icon-modern spf-icon-modern">&#128287;</div>
                                    <div class="protocol-info">
                                        <div class="protocol-name-modern">SPF</div>
                                        <div class="protocol-description-modern">Sender Policy Framework</div>
                                    </div>
                                </div>
                                <div class="protocol-result-modern $(if($result.EmailHeaderSPFResult -eq 'pass'){'protocol-pass-modern'}elseif($result.EmailHeaderSPFResult -eq 'fail'){'protocol-fail-modern'}else{'protocol-unknown-modern'})">
                                    <span class="protocol-status-icon-modern">$(if($result.EmailHeaderSPFResult -eq 'pass'){'&#10003;'}elseif($result.EmailHeaderSPFResult -eq 'fail'){'&#10007;'}else{'&#63;'})</span>
                                    <span class="protocol-status-text-modern">$(if($result.EmailHeaderSPFResult){$result.EmailHeaderSPFResult.ToUpper()}else{'UNKNOWN'})</span>
                                </div>
                                <div class="protocol-explanation-modern">
                                    $(switch ($result.EmailHeaderSPFResult.ToLower()) {
                                        'pass' { '&#x2705; The connecting IP address is allowed to send emails and configured in the SPF record' }
                                        'fail' { '&#x274C; The connecting IP address is not allowed to send emails and not configured in the SPF record' }
                                        'softfail' { '&#x26A0; The connecting IP address is not allowed to send emails and not configured in the SPF record, however emails will be accepted but marked [depends on the destination email system]' }
                                        'neutral' { '&#x2753; The SPF record specifies explicitly that nothing can be said about validity' }
                                        'none' { '&#x274C; The domain does not have an SPF record' }
                                        'permerror' { '&#x274C; There is incorrect syntax in the SPF record' }
                                        'temperror' { '&#x26A0; An error occurred while doing the SPF check like a DNS timeout' }
                                        default { '&#x2753; Authentication result unclear' }
                                    })
                                </div>
                            </div>

                            <div class="protocol-card-modern dkim-card">
                                <div class="protocol-header-modern">
                                    <div class="protocol-icon-modern dkim-icon-modern">&#128273;</div>
                                    <div class="protocol-info">
                                        <div class="protocol-name-modern">DKIM</div>
                                        <div class="protocol-description-modern">Digital Signature</div>
                                    </div>
                                </div>
                                <div class="protocol-result-modern $(if($result.EmailHeaderDKIMResult -eq 'pass'){'protocol-pass-modern'}elseif($result.EmailHeaderDKIMResult -eq 'fail'){'protocol-fail-modern'}else{'protocol-unknown-modern'})">
                                    <span class="protocol-status-icon-modern">$(if($result.EmailHeaderDKIMResult -eq 'pass'){'&#10003;'}elseif($result.EmailHeaderDKIMResult -eq 'fail'){'&#10007;'}else{'&#63;'})</span>
                                    <span class="protocol-status-text-modern">$(if($result.EmailHeaderDKIMResult){$result.EmailHeaderDKIMResult.ToUpper()}else{'UNKNOWN'})</span>
                                </div>
                                <div class="protocol-explanation-modern">
                                    $(switch ($result.EmailHeaderDKIMResult.ToLower()) {
                                        'pass' { '&#x2705; Email signature is valid' }
                                        'fail (signature did not verify)' { '&#x274C; One of the headers in the original DKIM signature has been modified' }
                                        'fail (body hash fail)' { '&#x274C; Something in between the sender and Mail Server modified the body after the DKIM signature was stamped on the message' }
                                        'fail' { '&#x274C; Email signature is invalid' }
                                        default { '&#x2753; Signature status unclear' }
                                    })
                                </div>
                            </div>

                            <div class="protocol-card-modern dmarc-card">
                                <div class="protocol-header-modern">
                                    <div class="protocol-icon-modern dmarc-icon-modern">&#128737;</div>
                                    <div class="protocol-info">
                                        <div class="protocol-name-modern">DMARC</div>
                                        <div class="protocol-description-modern">Policy Evaluation</div>
                                    </div>
                                </div>
                                <div class="protocol-result-modern $(if($result.EmailHeaderDMARCResult -eq 'pass'){'protocol-pass-modern'}elseif($result.EmailHeaderDMARCResult -eq 'fail'){'protocol-fail-modern'}else{'protocol-unknown-modern'})">
                                    <span class="protocol-status-icon-modern">$(if($result.EmailHeaderDMARCResult -eq 'pass'){'&#10003;'}elseif($result.EmailHeaderDMARCResult -eq 'fail'){'&#10007;'}else{'&#63;'})</span>
                                    <span class="protocol-status-text-modern">$(if($result.EmailHeaderDMARCResult){$result.EmailHeaderDMARCResult.ToUpper()}else{'UNKNOWN'})</span>
                                </div>
                                <div class="protocol-explanation-modern">
                                    $(if($result.EmailHeaderDMARCResult -eq 'pass'){'&#x2705; Policy evaluation passed'}
                                    elseif($result.EmailHeaderDMARCResult -eq 'fail'){'&#x274C; Policy evaluation failed'}
                                    else{'&#x2753; Policy evaluation unclear'})
                                </div>
                            </div>
$(if($result.EmailHeaderAction) {
"
                            <div class='protocol-card-modern action-card'>
                                <div class='protocol-header-modern'>
                                    <div class='protocol-icon-modern action-icon-modern'>&#128293;</div>
                                    <div class='protocol-info'>
                                        <div class='protocol-name-modern'>Action</div>
                                        <div class='protocol-description-modern'>DMARC Policy Action</div>
                                    </div>
                                </div>
                                <div class='protocol-result-modern $(if($result.EmailHeaderAction -eq 'none'){'protocol-pass-modern'}elseif($result.EmailHeaderAction -eq 'quarantine'){'protocol-warn-modern'}elseif($result.EmailHeaderAction -eq 'reject'){'protocol-fail-modern'}else{'protocol-info-modern'})'>
                                    <span class='protocol-status-icon-modern'>$(
                                        switch($result.EmailHeaderAction.ToLower()) {
                                            'none' { '&#10004;' }
                                            'quarantine' { '&#9888;' }
                                            'reject' { '&#10007;' }
                                            default { '&#128293;' }
                                        }
                                    )</span>
                                    <span class='protocol-status-text-modern'>$($result.EmailHeaderAction.ToUpper())</span>
                                </div>
                                <div class='protocol-explanation-modern'>
                                    $(switch($result.EmailHeaderAction.ToLower()) {
                                        'none' { '&#x2705; No action taken - message processed normally' }
                                        'quarantine' { '&#x26A0; Message quarantined or marked as suspicious' }
                                        'reject' { '&#x274C; Message rejected at SMTP level' }
                                        default { '&#x1F4CB; Action taken based on DMARC policy' }
                                    })
                                </div>
                            </div>"
})
$(if($result.EmailHeaderReason) {
"
                            <div class='protocol-card-modern reason-card'>
                                <div class='protocol-header-modern'>
                                    <div class='protocol-icon-modern reason-icon-modern'>&#128681;</div>
                                    <div class='protocol-info'>
                                        <div class='protocol-name-modern'>Reason</div>
                                        <div class='protocol-description-modern'>Authentication Reason Code</div>
                                    </div>
                                </div>
                                <div class='protocol-result-modern protocol-info-modern'>
                                    <span class='protocol-status-icon-modern'>&#128681;</span>
                                    <span class='protocol-status-text-modern'>$($result.EmailHeaderReason)</span>
                                </div>
                                <div class='protocol-explanation-modern'>
                                    &#x1F4CB; $(
                                        $reasonExplanation = Get-ReasonCodeExplanation -ReasonCode $result.EmailHeaderReason
                                        if ($reasonExplanation) {
                                            $reasonExplanation
                                        } else {
                                            "Detailed reason code for authentication result"
                                        }
                                    )
                                </div>
                            </div>"
})
$(if($result.EmailHeaderCompAuth) {
"
                            <div class='protocol-card-modern compauth-card'>
                                <div class='protocol-header-modern'>
                                    <div class='protocol-icon-modern compauth-icon-modern'>&#128273;</div>
                                    <div class='protocol-info'>
                                        <div class='protocol-name-modern'>CompAuth</div>
                                        <div class='protocol-description-modern'>Composite Authentication</div>
                                    </div>
                                </div>
                                <div class='protocol-result-modern protocol-info-modern'>
                                    <span class='protocol-status-icon-modern'>&#128273;</span>
                                    <span class='protocol-status-text-modern'>$($result.EmailHeaderCompAuth)</span>
                                </div>
                                <div class='protocol-explanation-modern'>
                                    &#x1F4CA; Microsoft's composite authentication result
                                </div>
                            </div>"
})
                        </div>

                        <!-- Additional Authentication Information -->
$(if($result.EmailHeaderAuthenticationResultsRaw) {
@"
                        <div class="additional-auth-info" style="margin-top: 25px; padding: 20px; background: rgba(255,255,255,0.95); border-radius: 10px; border: 1px solid #e9ecef;">
                            <h5 style="margin: 0 0 15px 0; color: #2c3e50; font-size: 1.1em; font-weight: 600; display: flex; align-items: center; gap: 10px;">
                                <span style="font-size: 1.2em;">&#128269;</span>
                                Additional Details
                            </h5>

                            <!-- Complete Authentication-Results Header -->
                            <div style='margin-bottom: 20px; padding: 15px; background: rgba(108,117,125,0.1); border-left: 4px solid #6c757d; border-radius: 0 8px 8px 0;'>
                                <div style='font-weight: 600; color: #495057; font-size: 1em; margin-bottom: 10px; display: flex; align-items: center; gap: 8px;'>
                                    <span style='font-size: 1.1em;'>&#128231;</span>
                                    Complete Authentication-Results Header
                                </div>
                                <div style='font-family: monospace; font-size: 0.85em; color: #495057; line-height: 1.4; background: rgba(248,249,250,0.8); padding: 12px; border-radius: 4px; word-break: break-all; border: 1px solid rgba(0,0,0,0.1);'>$(($result.EmailHeaderAuthenticationResultsRaw -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '[^\x20-\x7E]', '' -replace '\s+', ' ').Trim())</div>
                            </div>

                            <!-- X-MS-Office365-Filtering-Correlation-Id Header -->
$(if($result.EmailHeaderOffice365FilteringCorrelationId) {
"                            <div style='margin-bottom: 20px; padding: 15px; background: rgba(0, 123, 255, 0.1); border-left: 4px solid #007bff; border-radius: 0 8px 8px 0;'>
                                <div style='font-weight: 600; color: #0056b3; font-size: 1em; margin-bottom: 10px; display: flex; align-items: center; gap: 8px;'>
                                    <span style='font-size: 1.1em;'>&#128295;</span>
                                    Network Message ID
                                </div>
                                <div style='font-family: monospace; font-size: 0.85em; color: #0056b3; line-height: 1.4; background: rgba(248,249,250,0.8); padding: 12px; border-radius: 4px; word-break: break-all; border: 1px solid rgba(0,0,0,0.1);'>$($result.EmailHeaderOffice365FilteringCorrelationId)</div>


                            </div>"
})

                            <!-- X-Microsoft-Antispam-Mailbox-Delivery Header -->
$(if($result.EmailHeaderAntispamMailboxDelivery) {
"                            <div style='margin-bottom: 20px; padding: 15px; background: rgba(40, 167, 69, 0.1); border-left: 4px solid #28a745; border-radius: 0 8px 8px 0;'>
                                <div style='font-weight: 600; color: #155724; font-size: 1em; margin-bottom: 10px; display: flex; align-items: center; gap: 8px;'>
                                    <span style='font-size: 1.1em;'>&#128737;</span>
                                    X-Microsoft-Antispam-Mailbox-Delivery
                                </div>
                                <div style='font-family: monospace; font-size: 0.85em; color: #155724; line-height: 1.4; background: rgba(248,249,250,0.8); padding: 12px; border-radius: 4px; word-break: break-all; border: 1px solid rgba(0,0,0,0.1);'>$(($result.EmailHeaderAntispamMailboxDelivery -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '[^\x20-\x7E]', '' -replace '\s+', ' ').Trim())</div>

                                <!-- Individual Parameter Analysis -->
                                <div style='margin-top: 15px;'>
                                    <div style='font-weight: 600; color: #155724; font-size: 0.95em; margin-bottom: 12px;'>Parameter Analysis:</div>
                                    <div class='protocol-results-grid-modern'>
$(if($result.EmailHeaderAntispamUCF) {
"                                        <!-- UCF Parameter -->
                                        <div class='protocol-card-modern ucf-card'>
                                            <div class='protocol-header-modern'>
                                                <div class='protocol-icon-modern ucf-icon-modern'>&#128269;</div>
                                                <div class='protocol-info'>
                                                    <div class='protocol-name-modern'>UCF</div>
                                                    <div class='protocol-description-modern'>Unified Content Filter</div>
                                                </div>
                                            </div>
                                            <div class='protocol-result-modern $(if($result.EmailHeaderAntispamUCF -eq '0'){'protocol-pass-modern'}else{'protocol-fail-modern'})'>
                                                <span class='protocol-status-icon-modern'>$(if($result.EmailHeaderAntispamUCF -eq '0'){'&#10003;'}else{'&#10007;'})</span>
                                                <span class='protocol-status-text-modern'>$($result.EmailHeaderAntispamUCF)</span>
                                            </div>
                                            <div class='protocol-explanation-modern'>
                                                $(if($result.EmailHeaderAntispamUCF -eq '0'){'&#x2705; Content filter not applied - message passed initial checks'}else{'&#x274C; Content filter applied - security measures triggered'})
                                            </div>
                                        </div>"
})

$(if($result.EmailHeaderAntispamJMR) {
"                                        <!-- JMR Parameter -->
                                        <div class='protocol-card-modern jmr-card'>
                                            <div class='protocol-header-modern'>
                                                <div class='protocol-icon-modern jmr-icon-modern'>&#128235;</div>
                                                <div class='protocol-info'>
                                                    <div class='protocol-name-modern'>JMR</div>
                                                    <div class='protocol-description-modern'>Junk Mail Rule</div>
                                                </div>
                                            </div>
                                            <div class='protocol-result-modern $(if($result.EmailHeaderAntispamJMR -eq '0'){'protocol-pass-modern'}else{'protocol-fail-modern'})'>
                                                <span class='protocol-status-icon-modern'>$(if($result.EmailHeaderAntispamJMR -eq '0'){'&#10003;'}else{'&#10007;'})</span>
                                                <span class='protocol-status-text-modern'>$($result.EmailHeaderAntispamJMR)</span>
                                            </div>
                                            <div class='protocol-explanation-modern'>
                                                $(if($result.EmailHeaderAntispamJMR -eq '0'){'&#x2705; Junk mail rule not triggered - passed spam detection'}else{'&#x274C; Junk mail rule triggered - potential spam detected'})
                                            </div>
                                        </div>"
})

$(if($result.EmailHeaderAntispamDest) {
"                                        <!-- Dest Parameter -->
                                        <div class='protocol-card-modern dest-card'>
                                            <div class='protocol-header-modern'>
                                                <div class='protocol-icon-modern dest-icon-modern'>&#127919;</div>
                                                <div class='protocol-info'>
                                                    <div class='protocol-name-modern'>DEST</div>
                                                    <div class='protocol-description-modern'>Message Destination</div>
                                                </div>
                                            </div>
                                            <div class='protocol-result-modern $(if($result.EmailHeaderAntispamDest -eq 'I'){'protocol-pass-modern'}elseif($result.EmailHeaderAntispamDest -eq 'J' -or $result.EmailHeaderAntispamDest -eq 'D'){'protocol-fail-modern'}else{'protocol-unknown-modern'})'>
                                                <span class='protocol-status-icon-modern'>$(if($result.EmailHeaderAntispamDest -eq 'I'){'&#10003;'}elseif($result.EmailHeaderAntispamDest -eq 'J' -or $result.EmailHeaderAntispamDest -eq 'D'){'&#10007;'}else{'&#63;'})</span>
                                                <span class='protocol-status-text-modern'>$($result.EmailHeaderAntispamDest)</span>
                                            </div>
                                            <div class='protocol-explanation-modern'>
                                                $(if($result.EmailHeaderAntispamDest -eq 'I'){'&#x2705; Delivered to Inbox - successful delivery'}
                                                elseif($result.EmailHeaderAntispamDest -eq 'J'){'&#x274C; Delivered to Junk folder - spam detected'}
                                                elseif($result.EmailHeaderAntispamDest -eq 'D'){'&#x274C; Message deleted - high-confidence spam'}
                                                elseif($result.EmailHeaderAntispamDest -eq 'C'){'&#x2753; The message was delivered to the destination'}
                                                else{'&#x2753; Unknown destination routing'})
                                            </div>
                                        </div>"
})

$(if($result.EmailHeaderAntispamOFR) {
"                                        <!-- OFR Parameter -->
                                        <div class='protocol-card-modern ofr-card'>
                                            <div class='protocol-header-modern'>
                                                <div class='protocol-icon-modern ofr-icon-modern'>&#128200;</div>
                                                <div class='protocol-info'>
                                                    <div class='protocol-name-modern'>OFR</div>
                                                    <div class='protocol-description-modern'>Organizational Filter</div>
                                                </div>
                                            </div>
                                            <div class='protocol-result-modern $(if($result.EmailHeaderAntispamOFR -eq 'None'){'protocol-pass-modern'}elseif($result.EmailHeaderAntispamOFR -like '*CustomRules*'){'protocol-unknown-modern'}else{'protocol-fail-modern'})'>
                                                <span class='protocol-status-icon-modern'>$(if($result.EmailHeaderAntispamOFR -eq 'None'){'&#10003;'}elseif($result.EmailHeaderAntispamOFR -like '*CustomRules*'){'&#63;'}else{'&#10007;'})</span>
                                                <span class='protocol-status-text-modern'>$($result.EmailHeaderAntispamOFR)</span>
                                            </div>
                                            <div class='protocol-explanation-modern'>
                                                $(if($result.EmailHeaderAntispamOFR -eq 'None'){'&#x2705; No organizational rules applied - standard processing'}
                                                elseif($result.EmailHeaderAntispamOFR -like '*CustomRules*'){'&#x2753; Custom organizational rules applied (e.g., transport or mail flow rules)'}
                                                else{'&#x274C; Organizational filtering applied'})
                                            </div>
                                        </div>"
})
                                    </div>
                                </div>
                            </div>"
})

$(if($result.EmailHeaderForefrontAntispamReport) {
"                            <!-- X-Forefront-Antispam-Report-Untrusted Header -->
                            <div style='margin-bottom: 20px; padding: 15px; background: rgba(255, 193, 7, 0.1); border-left: 4px solid #ffc107; border-radius: 0 8px 8px 0;'>
                                <div style='font-weight: 600; color: #856404; font-size: 1em; margin-bottom: 10px; display: flex; align-items: center; gap: 8px;'>
                                    <span style='font-size: 1.1em;'>&#128187;</span>
                                    X-Forefront-Antispam-Report-Untrusted
                                </div>
                                <div style='font-family: monospace; font-size: 0.85em; color: #856404; line-height: 1.4; background: rgba(248,249,250,0.8); padding: 12px; border-radius: 4px; word-break: break-all; border: 1px solid rgba(0,0,0,0.1);'>$(($result.EmailHeaderForefrontAntispamReport -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '[^\x20-\x7E]', '' -replace '\s+', ' ').Trim())</div>

                                <!-- Individual Parameter Analysis -->
                                <div style='margin-top: 15px;'>
                                    <div style='font-weight: 600; color: #856404; font-size: 0.95em; margin-bottom: 12px;'>Parameter Analysis:</div>
                                    <div class='protocol-results-grid-modern'>
$(if($result.EmailHeaderForefrontCIP) {
"                                        <!-- CIP Parameter -->
                                        <div class='protocol-card-modern cip-card'>
                                            <div class='protocol-header-modern'>
                                                <div class='protocol-icon-modern cip-icon-modern'>&#127760;</div>
                                                <div class='protocol-info'>
                                                    <div class='protocol-name-modern'>CIP</div>
                                                    <div class='protocol-description-modern'>Client IP Address</div>
                                                </div>
                                            </div>
                                            <div class='protocol-result-modern protocol-info-modern'>
                                                <span class='protocol-status-icon-modern'>&#128205;</span>
                                                <span class='protocol-status-text-modern'>$($result.EmailHeaderForefrontCIP)</span>
                                            </div>
                                            <div class='protocol-explanation-modern'>
                                                &#128205; Source IP address of the connecting client
                                            </div>
                                        </div>"
})

$(if($result.EmailHeaderForefrontCTRY) {
"                                        <!-- CTRY Parameter -->
                                        <div class='protocol-card-modern ctry-card'>
                                            <div class='protocol-header-modern'>
                                                <div class='protocol-icon-modern ctry-icon-modern'>&#127757;</div>
                                                <div class='protocol-info'>
                                                    <div class='protocol-name-modern'>CTRY</div>
                                                    <div class='protocol-description-modern'>Country Code</div>
                                                </div>
                                            </div>
                                            <div class='protocol-result-modern protocol-info-modern'>
                                                <span class='protocol-status-icon-modern'>&#127482;</span>
                                                <span class='protocol-status-text-modern'>$($result.EmailHeaderForefrontCTRY)</span>
                                            </div>
                                            <div class='protocol-explanation-modern'>
                                                &#127482; Geographic country of origin for the sender
                                            </div>
                                        </div>"
})

$(if($result.EmailHeaderForefrontLANG) {
"                                        <!-- LANG Parameter -->
                                        <div class='protocol-card-modern lang-card'>
                                            <div class='protocol-header-modern'>
                                                <div class='protocol-icon-modern lang-icon-modern'>&#127482;</div>
                                                <div class='protocol-info'>
                                                    <div class='protocol-name-modern'>LANG</div>
                                                    <div class='protocol-description-modern'>Language Code</div>
                                                </div>
                                            </div>
                                            <div class='protocol-result-modern protocol-info-modern'>
                                                <span class='protocol-status-icon-modern'>&#128483;</span>
                                                <span class='protocol-status-text-modern'>$($result.EmailHeaderForefrontLANG)</span>
                                            </div>
                                            <div class='protocol-explanation-modern'>
                                                &#128483; Detected language of the email content
                                            </div>
                                        </div>"
})

$(if($result.EmailHeaderForefrontSCL) {
"                                        <!-- SCL Parameter -->
                                        <div class='protocol-card-modern scl-card'>
                                            <div class='protocol-header-modern'>
                                                <div class='protocol-icon-modern scl-icon-modern'>&#9888;</div>
                                                <div class='protocol-info'>
                                                    <div class='protocol-name-modern'>SCL</div>
                                                    <div class='protocol-description-modern'>Spam Confidence Level</div>
                                                </div>
                                            </div>
                                            <div class='protocol-result-modern $(if([int]$result.EmailHeaderForefrontSCL -le 4){'protocol-pass-modern'}elseif([int]$result.EmailHeaderForefrontSCL -le 6){'protocol-unknown-modern'}else{'protocol-fail-modern'})'>
                                                <span class='protocol-status-icon-modern'>$(if([int]$result.EmailHeaderForefrontSCL -le 4){'&#10003;'}elseif([int]$result.EmailHeaderForefrontSCL -le 6){'&#63;'}else{'&#10007;'})</span>
                                                <span class='protocol-status-text-modern'>$($result.EmailHeaderForefrontSCL)</span>
                                            </div>
                                            <div class='protocol-explanation-modern'>
                                                $(if([int]$result.EmailHeaderForefrontSCL -le 1){'&#x2705; Very low spam probability (0-1)'}
                                                elseif([int]$result.EmailHeaderForefrontSCL -le 4){'&#x2705; Low spam probability (2-4)'}
                                                elseif([int]$result.EmailHeaderForefrontSCL -le 6){'&#x2753; Medium spam probability (5-6)'}
                                                elseif([int]$result.EmailHeaderForefrontSCL -le 8){'&#x274C; High spam probability (7-8)'}
                                                else{'&#x274C; Very high spam probability'})
                                            </div>
                                        </div>"
})

$(if($result.EmailHeaderForefrontSRV) {
"                                        <!-- SRV Parameter -->
                                        <div class='protocol-card-modern srv-card'>
                                            <div class='protocol-header-modern'>
                                                <div class='protocol-icon-modern srv-icon-modern'>&#9881;</div>
                                                <div class='protocol-info'>
                                                    <div class='protocol-name-modern'>SRV</div>
                                                    <div class='protocol-description-modern'>Service Type</div>
                                                </div>
                                            </div>
                                            <div class='protocol-result-modern protocol-info-modern'>
                                                <span class='protocol-status-icon-modern'>&#9881;</span>
                                                <span class='protocol-status-text-modern'>$($result.EmailHeaderForefrontSRV)</span>
                                            </div>
                                            <div class='protocol-explanation-modern'>
                                                &#9881; Service or component that processed the message
                                            </div>
                                        </div>"
})

$(if($result.EmailHeaderForefrontIPV) {
"                                        <!-- IPV Parameter -->
                                        <div class='protocol-card-modern ipv-card'>
                                            <div class='protocol-header-modern'>
                                                <div class='protocol-icon-modern ipv-icon-modern'>&#127760;</div>
                                                <div class='protocol-info'>
                                                    <div class='protocol-name-modern'>IPV</div>
                                                    <div class='protocol-description-modern'>IP Version</div>
                                                </div>
                                            </div>
                                            <div class='protocol-result-modern protocol-info-modern'>
                                                <span class='protocol-status-icon-modern'>&#127760;</span>
                                                <span class='protocol-status-text-modern'>$($result.EmailHeaderForefrontIPV)</span>
                                            </div>
                                            <div class='protocol-explanation-modern'>
                                                $(switch($result.EmailHeaderForefrontIPV) {
                                                    'CAL' { '&#x2705; The message skipped spam filtering because the source IP address was in the IP Allow List' }
                                                    'NLI' { '&#x2139; The IP address was not found on any IP reputation list' }
                                                    default { '&#127760; IP protocol version (IPv4/IPv6) used by sender' }
                                                })
                                            </div>
                                        </div>"
})

$(if($result.EmailHeaderForefrontSFV) {
"                                        <!-- SFV Parameter -->
                                        <div class='protocol-card-modern sfv-card'>
                                            <div class='protocol-header-modern'>
                                                <div class='protocol-icon-modern sfv-icon-modern'>&#128737;</div>
                                                <div class='protocol-info'>
                                                    <div class='protocol-name-modern'>SFV</div>
                                                    <div class='protocol-description-modern'>Sender Filter Verdict</div>
                                                </div>
                                            </div>
                                            <div class='protocol-result-modern $(if($result.EmailHeaderForefrontSFV -eq 'NSPM'){'protocol-pass-modern'}else{'protocol-fail-modern'})'>
                                                <span class='protocol-status-icon-modern'>$(if($result.EmailHeaderForefrontSFV -eq 'NSPM'){'&#10003;'}else{'&#10007;'})</span>
                                                <span class='protocol-status-text-modern'>$($result.EmailHeaderForefrontSFV)</span>
                                            </div>
                                            <div class='protocol-explanation-modern'>
                                                $(if($result.EmailHeaderForefrontSFV -eq 'NSPM'){'&#x2705; Not Spam - message passed sender filtering'}
                                                else{'&#x274C; Sender filtering applied - potential spam detected'})
                                            </div>
                                        </div>"
})

$(if($result.EmailHeaderForefrontPTR) {
"                                        <!-- PTR Parameter -->
                                        <div class='protocol-card-modern ptr-card'>
                                            <div class='protocol-header-modern'>
                                                <div class='protocol-icon-modern ptr-icon-modern'>&#128260;</div>
                                                <div class='protocol-info'>
                                                    <div class='protocol-name-modern'>PTR</div>
                                                    <div class='protocol-description-modern'>Reverse DNS</div>
                                                </div>
                                            </div>
                                            <div class='protocol-result-modern protocol-info-modern'>
                                                <span class='protocol-status-icon-modern'>&#128260;</span>
                                                <span class='protocol-status-text-modern'>$(if($result.EmailHeaderForefrontPTR){$result.EmailHeaderForefrontPTR}else{'Not Available'})</span>
                                            </div>
                                            <div class='protocol-explanation-modern'>
                                                &#128260; Reverse DNS lookup result for sender IP address
                                            </div>
                                        </div>"
})

$(if($result.EmailHeaderForefrontCAT) {
"                                        <!-- CAT Parameter -->
                                        <div class='protocol-card-modern cat-card'>
                                            <div class='protocol-header-modern'>
                                                <div class='protocol-icon-modern cat-icon-modern'>&#128193;</div>
                                                <div class='protocol-info'>
                                                    <div class='protocol-name-modern'>CAT</div>
                                                    <div class='protocol-description-modern'>Category</div>
                                                </div>
                                            </div>
                                            <div class='protocol-result-modern protocol-info-modern'>
                                                <span class='protocol-status-icon-modern'>&#128193;</span>
                                                <span class='protocol-status-text-modern'>$($result.EmailHeaderForefrontCAT)</span>
                                            </div>
                                            <div class='protocol-explanation-modern'>
                                                $(switch ($result.EmailHeaderForefrontCAT) {
                                                    'AMP' { '&#9888; Anti-malware - Malicious software detected' }
                                                    'BIMP' { '&#9888; Brand impersonation - Impersonating known brands' }
                                                    'BULK' { '&#128236; Bulk - Mass mailing detected' }
                                                    'DIMP' { '&#9888; Domain impersonation - Impersonating trusted domains' }
                                                    'FTBP' { '&#128193; Anti-malware common attachments filter - Common attachment types filtered' }
                                                    'GIMP' { '&#9888; Mailbox intelligence impersonation - AI-detected impersonation attempt' }
                                                    'HPHSH' { '&#128308; High confidence phishing - High-risk phishing attempt' }
                                                    'HPHISH' { '&#128308; High confidence phishing - High-risk phishing attempt' }
                                                    'HSPM' { '&#128308; High confidence spam - High-risk spam content' }
                                                    'INTOS' { '&#9888; Intra-Organization phishing - Internal phishing attempt' }
                                                    'MALW' { '&#128308; Malware - Malicious software detected' }
                                                    'OSPM' { '&#128236; Outbound spam - Outgoing spam detected' }
                                                    'PHSH' { '&#9888; Phishing - Phishing attempt detected' }
                                                    'SAP' { '&#128737; Safe Attachments - Attachment security analysis' }
                                                    'SPM' { '&#128236; Spam - Unsolicited bulk email' }
                                                    'SPOOF' { '&#9888; Spoofing - Email address spoofing detected' }
                                                    'UIMP' { '&#9888; User impersonation - Impersonating specific users' }
                                                    default { "&#128193; $($result.EmailHeaderForefrontCAT) - Message category classification" }
                                                })
                                            </div>
                                        </div>"
})

$(if($result.EmailHeaderForefrontDIR) {
"                                        <!-- DIR Parameter -->
                                        <div class='protocol-card-modern dir-card'>
                                            <div class='protocol-header-modern'>
                                                <div class='protocol-icon-modern dir-icon-modern'>&#10145;</div>
                                                <div class='protocol-info'>
                                                    <div class='protocol-name-modern'>DIR</div>
                                                    <div class='protocol-description-modern'>Direction</div>
                                                </div>
                                            </div>
                                            <div class='protocol-result-modern protocol-info-modern'>
                                                <span class='protocol-status-icon-modern'>&#10145;</span>
                                                <span class='protocol-status-text-modern'>$($result.EmailHeaderForefrontDIR)</span>
                                            </div>
                                            <div class='protocol-explanation-modern'>
                                                &#10145; Message flow direction (inbound/outbound)
                                            </div>
                                        </div>"
})

$(if($result.EmailHeaderForefrontSFP) {
"                                        <!-- SFP Parameter -->
                                        <div class='protocol-card-modern sfp-card'>
                                            <div class='protocol-header-modern'>
                                                <div class='protocol-icon-modern sfp-icon-modern'>&#128220;</div>
                                                <div class='protocol-info'>
                                                    <div class='protocol-name-modern'>SFP</div>
                                                    <div class='protocol-description-modern'>Sender Filter Policy</div>
                                                </div>
                                            </div>
                                            <div class='protocol-result-modern protocol-info-modern'>
                                                <span class='protocol-status-icon-modern'>&#128220;</span>
                                                <span class='protocol-status-text-modern'>$($result.EmailHeaderForefrontSFP)</span>
                                            </div>
                                            <div class='protocol-explanation-modern'>
                                                &#128220; Sender filtering policy result
                                            </div>
                                        </div>"
})
                                    </div>
                                </div>
                            </div>"
})
                        </div>
"@
})
                    </div>
                </div>

                <!-- Step 2: Domain Information -->
                <div class="auth-step-clear step-2">
                    <div class="step-header-modern">
                        <div class="step-indicator">
                            <span class="step-number-modern">2</span>
                            <div class="step-connector"></div>
                        </div>
                        <div class="step-content-header">
                            <h4 class="step-title-modern">Domain Alignment Analysis</h4>
                            <p class="step-description">Verify that email domains are properly aligned</p>
                        </div>
                    </div>
                    <div class="step-body">
                        <div class="domain-alignment-explanation-modern">
                            <div class="info-box">
                                <span class="info-icon">&#x1F4A1;</span>
                                <span>Domains can be aligned if MailFrom (P1) matches From (P2)</span>
                            </div>
                        </div>
                        <div class="domain-comparison-ultra-modern">
                            <div class="domain-pair-modern single-pair">
                                <div class="domain-info-card-modern envelope-card">
                                    <div class="domain-card-header-modern">
                                        <span class="domain-icon-modern">&#128232;</span>
                                        <div class="domain-type-info">
                                            <span class="domain-type-modern">MailFrom (P1) - smtp.mailfrom [What is shown in the header]</span>
                                            <span class="domain-type-desc">Technical sender address</span>
                                        </div>
                                    </div>
                                    <div class="domain-value-display-modern">$(if($result.EmailHeaderSMTPMailFrom){$result.EmailHeaderSMTPMailFrom}else{'Not Found'})</div>
                                </div>

                                <div class="alignment-arrow-modern">
                                    <div class="arrow-line"></div>
                                    <span class="arrow-icon-modern">&#8596;</span>
                                    <span class="alignment-text-modern">Must Match</span>
                                    <div class="arrow-line"></div>
                                </div>

                                <div class="domain-info-card-modern header-card">
                                    <div class="domain-card-header-modern">
                                        <span class="domain-icon-modern">&#128228;</span>
                                        <div class="domain-type-info">
                                            <span class="domain-type-modern">From (P2) - header.from [What mail client (Outlook) shows]</span>
                                            <span class="domain-type-desc">What users see</span>
                                        </div>
                                    </div>
                                    <div class="domain-value-display-modern">$(if($result.EmailHeaderHeaderFrom){$result.EmailHeaderHeaderFrom}else{'Not Found'})</div>
                                </div>

                                <div class="alignment-status-modern">
                                    <div class="alignment-result-modern $(if($result.EmailHeaderHeaderFrom -and $result.EmailHeaderSMTPMailFrom -and $result.EmailHeaderHeaderFrom.ToLower() -eq $result.EmailHeaderSMTPMailFrom.ToLower()){'alignment-pass-modern'}else{'alignment-fail-modern'})">
                                        <span class="alignment-icon-modern">$(if($result.EmailHeaderHeaderFrom -and $result.EmailHeaderSMTPMailFrom -and $result.EmailHeaderHeaderFrom.ToLower() -eq $result.EmailHeaderSMTPMailFrom.ToLower()){'&#10003;'}else{'&#10007;'})</span>
                                        <div class="alignment-text-container">
                                            <span class="alignment-label-modern">$(if($result.EmailHeaderHeaderFrom -and $result.EmailHeaderSMTPMailFrom -and $result.EmailHeaderHeaderFrom.ToLower() -eq $result.EmailHeaderSMTPMailFrom.ToLower()){'Properly Aligned'}else{'Not Aligned'})</span>
                                            <span class="alignment-detail">$(if($result.EmailHeaderHeaderFrom -and $result.EmailHeaderSMTPMailFrom -and $result.EmailHeaderHeaderFrom.ToLower() -eq $result.EmailHeaderSMTPMailFrom.ToLower()){'Domains match exactly'}else{if($result.EmailHeaderHeaderFrom -and $result.EmailHeaderSMTPMailFrom){'Domain mismatch detected'}else{'Missing domain information'}})</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Step 3: DMARC Pass Conditions -->
                <div class="auth-step-clear step-3">
                    <div class="step-header-modern">
                        <div class="step-indicator">
                            <span class="step-number-modern">3</span>
                            <div class="step-connector"></div>
                        </div>
                        <div class="step-content-header">
                            <h4 class="step-title-modern">DMARC Pass Evaluation</h4>
                            <p class="step-description">Check DMARC Passing conditions</p>
                        </div>
                    </div>
                    <div class="step-body">
                        <div class="dmarc-conditions-explanation-modern">
                            <div class="info-box">
                                <span class="info-icon">&#x26A1;</span>
                                <span>DMARC passes when <strong>at least ONE</strong> of these conditions is met:</span>
                            </div>
                        </div>

                        <div class="conditions-container-modern">
                            <!-- Condition 1 -->
                            <div class="condition-ultra-modern $(if($result.EmailHeaderCondition1Met){'condition-success-modern'}else{'condition-failure-modern'})">
                                <div class="condition-main-header-modern">
                                    <div class="condition-number-modern">A</div>
                                    <div class="condition-title-section-modern">
                                        <div class="condition-title-main">SPF Authentication Path</div>
                                        <div class="condition-subtitle-modern">SPF passes and From (P2) matches MailFrom (P1)</div>
                                    </div>
                                    <div class="condition-main-status-modern">
                                        <span class="main-status-badge-modern $(if($result.EmailHeaderCondition1Met){'status-met-modern'}else{'status-not-met-modern'})">
                                            $(if($result.EmailHeaderCondition1Met){'&#10003; MET'}else{'&#10007; NOT MET'})
                                        </span>
                                    </div>
                                </div>
                                <div class="condition-requirements-modern">
                                    <div class="requirement-item-modern $(if($result.EmailHeaderSPFResult -eq 'pass'){'requirement-met-modern'}else{'requirement-not-met-modern'})">
                                        <span class="requirement-icon-modern">$(if($result.EmailHeaderSPFResult -eq 'pass'){'&#10003;'}else{'&#10007;'})</span>
                                        <span class="requirement-text-modern">SPF Result: <strong>$(if($result.EmailHeaderSPFResult){$result.EmailHeaderSPFResult.ToUpper()}else{'UNKNOWN'})</strong></span>
                                    </div>
                                    <div class="requirement-item-modern $(if($result.EmailHeaderHeaderFrom -and $result.EmailHeaderSMTPMailFrom -and $result.EmailHeaderHeaderFrom.ToLower() -eq $result.EmailHeaderSMTPMailFrom.ToLower()){'requirement-met-modern'}else{'requirement-not-met-modern'})">
                                        <span class="requirement-icon-modern">$(if($result.EmailHeaderHeaderFrom -and $result.EmailHeaderSMTPMailFrom -and $result.EmailHeaderHeaderFrom.ToLower() -eq $result.EmailHeaderSMTPMailFrom.ToLower()){'&#10003;'}else{'&#10007;'})</span>
                                        <span class="requirement-text-modern">Domain Alignment: From (P2) = MailFrom (P1)</span>
                                    </div>
                                </div>
                            </div>

                            <!-- OR Separator -->
                            <div class="or-separator-modern">
                                <div class="or-line"></div>
                                <span class="or-text-modern">OR</span>
                                <div class="or-line"></div>
                            </div>

                            <!-- Condition 2 -->
                            <div class="condition-ultra-modern $(if($result.EmailHeaderCondition2Met){'condition-success-modern'}else{'condition-failure-modern'})">
                                <div class="condition-main-header-modern">
                                    <div class="condition-number-modern">B</div>
                                    <div class="condition-title-section-modern">
                                        <div class="condition-title-main">DKIM Authentication Path</div>
                                        <div class="condition-subtitle-modern">DKIM passes and the DKIM signature (header.d) is signed by the From (P2) domain</div>
                                    </div>
                                    <div class="condition-main-status-modern">
                                        <span class="main-status-badge-modern $(if($result.EmailHeaderCondition2Met){'status-met-modern'}else{'status-not-met-modern'})">
                                            $(if($result.EmailHeaderCondition2Met){'&#10003; MET'}else{'&#10007; NOT MET'})
                                        </span>
                                    </div>
                                </div>
                                <div class="condition-requirements-modern">
                                    <div class="requirement-item-modern $(if($result.EmailHeaderDKIMResult -eq 'pass'){'requirement-met-modern'}else{'requirement-not-met-modern'})">
                                        <span class="requirement-icon-modern">$(if($result.EmailHeaderDKIMResult -eq 'pass'){'&#10003;'}else{'&#10007;'})</span>
                                        <span class="requirement-text-modern">DKIM Result: <strong>$(if($result.EmailHeaderDKIMResult){$result.EmailHeaderDKIMResult.ToUpper()}else{'UNKNOWN'})</strong></span>
                                    </div>
                                    <div class="requirement-item-modern $(if($result.EmailHeaderHeaderD -and $result.EmailHeaderSMTPMailFrom -and $result.EmailHeaderHeaderD.ToLower() -eq $result.EmailHeaderSMTPMailFrom.ToLower()){'requirement-met-modern'}else{'requirement-not-met-modern'})">
                                        <span class="requirement-icon-modern">$(if($result.EmailHeaderHeaderD -and $result.EmailHeaderSMTPMailFrom -and $result.EmailHeaderHeaderD.ToLower() -eq $result.EmailHeaderSMTPMailFrom.ToLower()){'&#10003;'}else{'&#10007;'})</span>
                                        <span class="requirement-text-modern">Domain Alignment: DKIM signature (header.d) is signed by the From (P2) domain</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Final Summary -->
                <div class="auth-step-clear step-4">
                    <div class="step-header-modern">
                        <div class="step-indicator final">
                            <span class="step-number-modern">4</span>
                        </div>
                        <div class="step-content-header">
                            <h4 class="step-title-modern">Final Authentication Result</h4>
                            <p class="step-description">Overall authentication outcome</p>
                        </div>
                    </div>
                    <div class="step-body">
                        <div class="final-result-ultra-modern">
                            <div class="final-result-content-modern $(if($result.EmailHeaderDMARCPass -eq 'Yes'){'final-success-modern'}else{'final-failure-modern'})">
                                <div class="final-result-icon-modern">
                                    $(if($result.EmailHeaderDMARCPass -eq 'Yes'){'&#127881;'}else{'&#9888;'})
                                </div>
                                <div class="final-result-text-modern">
                                    <div class="final-result-title-modern">
                                        $(if($result.EmailHeaderDMARCPass -eq 'Yes') {
                                            if($result.EmailHeaderCondition1Met -and $result.EmailHeaderCondition2Met) {
                                                'EXCELLENT: DMARC AUTHENTICATION PASSED'
                                            } else {
                                                'GOOD: DMARC AUTHENTICATION PASSED'
                                            }
                                        } else {
                                            'DMARC AUTHENTICATION FAILED'
                                        })
                                    </div>
                                    <div class="final-result-explanation-modern">
                                        $(if($result.EmailHeaderDMARCPass -eq 'Yes') {
                                            if($result.EmailHeaderCondition1Met -and $result.EmailHeaderCondition2Met) {
                                                '&#x1F3AF; Both SPF and DKIM authentication paths succeeded. This email has the highest level of authentication confidence and should be trusted by email systems.'
                                            } else {
                                                '&#x2705; At least one authentication path (SPF or DKIM) succeeded with proper domain alignment. This email passed DMARC requirements and should be delivered normally.'
                                            }
                                        } else {
                                            '&#x26A0;&#xFE0F; Neither authentication path succeeded with proper domain alignment. This email may be treated as suspicious, quarantined, or rejected by email systems depending on the domain''s DMARC policy.'
                                        })
                                    </div>
                                </div>
                                <div class="final-result-actions">
                                    <div class="action-recommendation">
                                        $(if($result.EmailHeaderDMARCPass -eq 'Yes') {
                                            '&#x2709;&#xFE0F; Email should be delivered to inbox'
                                        } else {
                                            '&#x1F6AB; Email may be blocked or sent to spam'
                                        })
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
"@
})

        </div>
"@
}

# Add consolidated footer sections after all domains
$html += "        </div>"  # Close content div

# Add footer section with "Understanding Your Results" (appears only once)
$html += '    <div class="footer">'
$html += "        <h3>&#128202; Understanding Your Results</h3>"
$html += '        <div style="background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); border: 1px solid #dee2e6; border-radius: 10px; padding: 20px; margin: 20px 0;">'
$html += '            <h4 style="margin-top: 0; color: #495057; display: flex; align-items: center; gap: 10px;"><span style="font-size: 1.2em;">&#9881;</span>Granular Scoring System</h4>'
$html += '            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 15px; margin-top: 15px;">'
$html += '                <div style="background: rgba(255,193,7,0.1); border-left: 4px solid #ffc107; padding: 15px; border-radius: 0 8px 8px 0;">'
$html += '                    <strong style="color: #856404; font-size: 1.1em;">SPF (40 points total)</strong><br>'
$html += '                    <span style="color: #856404; font-size: 0.9em;">&#8226; Record Present: <strong>8 points</strong><br>&#8226; Other 8 checks: <strong>4 points each</strong></span>'
$html += '                </div>'
$html += '                <div style="background: rgba(23,162,184,0.1); border-left: 4px solid #17a2b8; padding: 15px; border-radius: 0 8px 8px 0;">'
$html += '                    <strong style="color: #0c5460; font-size: 1.1em;">DMARC (30 points total)</strong><br>'
$html += '                    <span style="color: #0c5460; font-size: 0.9em;">&#8226; Each of 5 checks: <strong>6 points each</strong><br>&#8226; Includes policy strength validation</span>'
$html += '                </div>'
$html += '                <div style="background: rgba(111,66,193,0.1); border-left: 4px solid #6f42c1; padding: 15px; border-radius: 0 8px 8px 0;">'
$html += '                    <strong style="color: #495057; font-size: 1.1em;">DKIM (30 points total)</strong><br>'
$html += '                    <span style="color: #495057; font-size: 0.9em;">&#8226; Each of 5 checks: <strong>6 points each</strong><br>&#8226; Key strength and TTL validation</span>'
$html += '                </div>'
$html += '            </div>'
$html += '            <p style="margin: 15px 0 0 0; color: #6c757d; font-size: 0.9em; text-align: center;">Maximum possible score: <strong>100 points</strong> (40 + 30 + 30)</p>'
$html += '        </div>'
$html += '        <div class="legend">'
$html += '            <div class="legend-item">'
$html += '                <span class="status-excellent">Excellent (95+ with DMARC reject)</span><br>'
$html += "                <small>All records optimally configured with strict DMARC policy</small>"
$html += "            </div>"
$html += '            <div class="legend-item">'
$html += '                <span class="status-good">Good (85-94)</span><br>'
$html += "                <small>Well configured but may need DMARC policy upgrade</small>"
$html += "            </div>"
$html += '            <div class="legend-item">'
$html += '                <span class="status-fair">Fair (65-84)</span><br>'
$html += "                <small>Some security gaps present, improvements needed</small>"
$html += "            </div>"
$html += '            <div class="legend-item">'
$html += '                <span class="status-poor">Poor (40-64)</span><br>'
$html += "                <small>Significant security vulnerabilities</small>"
$html += "            </div>"
$html += '            <div class="legend-item">'
$html += '                <span class="status-critical">Critical (&lt;40)</span><br>'
$html += "                <small>Urgent attention required - major security risks</small>"
$html += "            </div>"
$html += "        </div>"
$html += '        <hr style="margin: 25px 0; border: none; border-top: 1px solid #ddd;">'
$html += '        <p style="color: #888; font-size: 0.9em;">'
$html += "            &#128231; Email Authentication Checker v1.5 (Enhanced Provider-Aware Analysis) | Generated on $reportDate at $(Get-Date -Format 'HH:mm:ss')"
$html += "        </p>"
$html += "    </div>"
$html += "    </div>"
$html += "</body>"
$html += "</html>"

# Save HTML report to selected location (moved outside the foreach loop)
$reportFileName = "Email-Auth-Report-$fileTimestamp.html"
$reportPath = Join-Path -Path $path -ChildPath $reportFileName

# Save the HTML file
$html | Out-File -FilePath $reportPath -Encoding UTF8 -Force

Write-Host ""
Write-Host "HTML report successfully generated!" -ForegroundColor Green
Write-Host "Report saved to: $reportPath" -ForegroundColor Cyan
Write-Host ""

# Display final summary
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "              FINAL SUMMARY" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Total domains analyzed: $totalDomains" -ForegroundColor White
Write-Host "Average security score: $avgScore/100" -ForegroundColor White
Write-Host ""

# Open the report based on parameter
if ($AutoOpen) {
    Start-Process $reportPath
    Write-Host "Opening report in your default browser..." -ForegroundColor Green
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    return  # Exit the script only, keep PowerShell window open
} else {
    Write-Host "Report generated successfully. Use -AutoOpen parameter to automatically open the report." -ForegroundColor Green
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
}
