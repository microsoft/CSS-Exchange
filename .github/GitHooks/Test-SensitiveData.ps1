# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Scans test data files for sensitive data patterns.
.DESCRIPTION
    Checks staged test data files for email addresses and domain names outside
    allowed test domains, public IP addresses, and credential-like patterns.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string[]]$Files
)

$failed = $false

# RFC-reserved TLDs that can't be publicly registered (safe for test data)
# cspell:ignore Tlds
$reservedTlds = @('local', 'test', 'example', 'invalid', 'localhost', 'internal', 'lan')

# Allowed domains in test data (entries are regex fragments with escaped dots)
# cspell:ignore vnext apikey fabrikam microsoftonline cloudapp
$allowedDomains = @(
    'fabrikam\.com',
    'example\.com',
    'contoso\.com',
    'contoso\.lab',
    'contoso\.mail\.onmicrosoft\.com',
    # Microsoft service domains (product constants in Exchange configuration)
    'microsoft\.com',
    'microsoftonline-p\.com',
    'microsoftonline\.com',
    'outlook\.com',
    'live\.com',
    'live-int\.com',
    'office365\.com',
    'office\.com',
    'msn\.com',
    'passport\.com',
    'cloudapp\.net'
)
$allowedDomainsPattern = $allowedDomains -join '|'

# Non-public IP ranges: RFC 1918 + loopback + APIPA + CGNAT + TEST-NET + benchmark + multicast + broadcast
# cspell:ignore APIPA CGNAT
$privateIpPattern = '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|255\.255\.255\.255|169\.254\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|198\.1[89]\.|22[4-9]\.|2[3-5][0-9]\.)'

# Specific email addresses that are allowed regardless of domain
$allowedEmails = @(
    'ExToolsFeedback@microsoft.com'
)

foreach ($file in $Files) {
    if (-not (Test-Path $file)) { continue }

    try {
        $lines = @(Get-Content -Path $file -ErrorAction Stop)
    } catch {
        Write-Host "  BLOCKED: $file - Unable to read file: $($_.Exception.Message)" -ForegroundColor Red
        $failed = $true
        continue
    }
    if ($lines.Count -eq 0) { continue }

    $domainsInFile = @{}

    # Patterns defined once outside the per-line loop for performance
    $tldPattern = '(com|net|org|edu|gov|io|info|biz|co|us|uk|de|au|ca|jp|fr|in|eu|cloud|app|dev|lab)'
    $fqdnRegex = '(?i)\b([a-zA-Z0-9][a-zA-Z0-9-]*(?:\.[a-zA-Z0-9-]+)*\.' + $tldPattern + ')\b'
    $credentialKeywords = 'password|secret|apikey|token|credential'
    $safeValues = @('true', 'false', 'Enabled', 'Disabled', 'Changed', 'None', 'NotConfigured')
    $assignRegex = '(?i)\b(?:' + $credentialKeywords + ')\s*[:=]\s*[''"]([^''"]+)[''"]'
    $xmlAttrRegex = '(?i)(?:key|name)\s*=\s*[''"](?:' + $credentialKeywords + ')[''"].*?value\s*=\s*[''"]([^''"]+)[''"]'
    # cspell:ignore clixml
    $clixmlRegex = '(?i)N\s*=\s*[''"](?:' + $credentialKeywords + ')[''"]>([^<]+)<'

    $lineNumber = 0
    foreach ($line in $lines) {
        $lineNumber++

        # Check for email addresses outside allowed domains
        $emailMatches = [regex]::Matches($line, '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        foreach ($match in $emailMatches) {
            if ($match.Value -in $allowedEmails) { continue }
            $emailTld = ($match.Value -split '\.')[-1].ToLower()
            if ($emailTld -in $reservedTlds) { continue }
            if ($match.Value -notmatch "@(?:.*\.)?($allowedDomainsPattern)$") {
                Write-Host "  BLOCKED: $file`:$lineNumber - Unrecognized email domain: $($match.Value)" -ForegroundColor Red
                $failed = $true
            }
        }

        # Check for bare domain names outside allowed domains
        # Skip XML namespaces, .NET assembly/binary contexts, and known product strings
        # cspell:ignore fqdn msilog microsft
        # Note: \\Microsft\.Net\\ is a known typo in the default IIS web.config comment template
        # shipped with Exchange ("located in \Windows\Microsft.Net\Frameworks\v2.x\Config")
        if ($line -notmatch 'xmlns|assembly|codeBase|PublicKeyToken|\.dll|\.exe|\\Microsoft\.NET\\|\\Microsft\.Net\\|ASP\.NET|WMI\.NET|\.msilog') {
            # Match FQDNs ending in known public TLDs
            $fqdnMatches = [regex]::Matches($line, $fqdnRegex)
            foreach ($fqdnMatch in $fqdnMatches) {
                $fqdn = $fqdnMatch.Groups[1].Value
                # Skip Windows file paths and email domain portions (already checked by email scanner)
                $matchIndex = $fqdnMatch.Index
                if ($matchIndex -ge 1 -and $line.Substring($matchIndex - 1, 1) -in @('\', '@')) { continue }
                if ($fqdn -match '(?i)^System\.') { continue }
                if ($fqdn -notmatch "(?i)(?:^|\.)($allowedDomainsPattern)$") {
                    $fqdnLower = $fqdn.ToLower()
                    if (-not $domainsInFile.ContainsKey($fqdnLower)) {
                        $domainsInFile[$fqdnLower] = 0
                    }
                    $domainsInFile[$fqdnLower]++
                }
            }
        }

        # Check for public IP addresses - only on lines that look like network/address context
        # CLIXML files contain many dotted-quad version numbers (assembly versions, OIDs, etc.)
        # so we only flag IPs on lines with network-related property names
        if ($line -match 'Address|IPAddress|IPRange|Subnet|Gateway|DNS|Binding|Proxy|SmartHost|Remote|Endpoint') {
            $ipMatches = [regex]::Matches($line, '\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
            foreach ($match in $ipMatches) {
                $ip = $match.Value
                $octets = $ip -split '\.'
                # Skip if first octet is 0 or any octet > 255 (not a valid IP)
                if ([int]$octets[0] -eq 0 -or ($octets | Where-Object { [int]$_ -gt 255 }).Count -gt 0) { continue }
                # Skip subnet masks
                if ($ip -match '^255\.') { continue }
                # Skip version-like patterns
                if ($line -match 'Version|Build|FileVersion|ProductVersion|ExchangeBuild') { continue }
                if ($ip -notmatch $privateIpPattern) {
                    Write-Host "  BLOCKED: $file`:$lineNumber - Public IP address: $ip" -ForegroundColor Red
                    $failed = $true
                }
            }
        }

        # Check for credential patterns in multiple formats
        $credentialFound = $false

        # Assignment form: password = "value", secret: 'value'
        $assignMatches = [regex]::Matches($line, $assignRegex)
        foreach ($m in $assignMatches) {
            if ($m.Groups[1].Value -notin $safeValues) {
                $credentialFound = $true
                break
            }
        }

        # XML attribute form: key="password" value="secret"
        if (-not $credentialFound) {
            $xmlAttrMatches = [regex]::Matches($line, $xmlAttrRegex)
            foreach ($m in $xmlAttrMatches) {
                if ($m.Groups[1].Value -notin $safeValues) {
                    $credentialFound = $true
                    break
                }
            }
        }

        # CLIXML element form: N="Password">value</
        if (-not $credentialFound) {
            $clixmlMatches = [regex]::Matches($line, $clixmlRegex)
            foreach ($m in $clixmlMatches) {
                if ($m.Groups[1].Value.Trim() -notin $safeValues) {
                    $credentialFound = $true
                    break
                }
            }
        }

        if ($credentialFound) {
            Write-Host "  BLOCKED: $file`:$lineNumber - Possible credential value detected" -ForegroundColor Red
            $failed = $true
        }
    }

    # Report unrecognized domains found in this file (one line per domain)
    foreach ($entry in $domainsInFile.GetEnumerator() | Sort-Object -Property Value -Descending) {
        Write-Host "  BLOCKED: $file - Unrecognized domain: $($entry.Key) ($($entry.Value) occurrences)" -ForegroundColor Red
        $failed = $true
    }
}

if ($failed) {
    Write-Host "`nSensitive data check failed. Review flagged items above." -ForegroundColor Red
    return 1
} else {
    Write-Host "  No sensitive data found." -ForegroundColor Green
    return 0
}
