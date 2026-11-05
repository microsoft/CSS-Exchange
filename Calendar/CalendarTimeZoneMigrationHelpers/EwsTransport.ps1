# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# cspell:ignore faultcode faultstring tzone servicebindinginformation inet Guids psbase Dacl sids

$script:TypesNamespace = 'http://schemas.microsoft.com/exchange/services/2006/types'
$script:MessagesNamespace = 'http://schemas.microsoft.com/exchange/services/2006/messages'
# Stored on migrated items. Never change this value: existing markers and receipts are found by it.
$script:MIGRATION_PROPERTY_SET_ID = '8b4b6a17-ed03-48ae-8977-306959b21fe5'
$script:MigrationStateFieldUri = '<t:ExtendedFieldURI PropertySetId="' + $script:MIGRATION_PROPERTY_SET_ID + '" PropertyName="CalendarTimeZoneMigrationState" PropertyType="String"/>'
$script:MigrationReceiptFieldUri = '<t:ExtendedFieldURI PropertySetId="' + $script:MIGRATION_PROPERTY_SET_ID + '" PropertyName="CalendarTimeZoneMigrationReceipt" PropertyType="String"/>'
$script:MAX_THROTTLING_RETRIES = 6
$script:MAX_BACKOFF_SECONDS = 300
# Set by the entry script or development loader; recorded in every run manifest.
$script:ExOPRuntimeVersion = 'development'
$script:ExOPRuntimeFiles = @()

function ConvertTo-ExOPXmlText {
    param (
        [AllowNull()]
        [string]
        $Value
    )
    if ($null -eq $Value) { return '' }
    [Security.SecurityElement]::Escape($Value)
}

function Get-ExOPNamespaceManager {
    param (
        [Parameter(Mandatory)]
        [System.Xml.XmlNode]
        $Node
    )
    $document = if ($Node -is [xml]) { $Node } else { $Node.OwnerDocument }
    $manager = New-Object System.Xml.XmlNamespaceManager($document.NameTable)
    $manager.AddNamespace('t', $script:TypesNamespace)
    $manager.AddNamespace('m', $script:MessagesNamespace)
    $manager.AddNamespace('s', 'http://schemas.xmlsoap.org/soap/envelope/')
    return , $manager
}

function Get-ExOPText {
    param (
        [System.Xml.XmlNode]
        $Node,

        [string]
        $Path
    )
    $value = $Node.SelectSingleNode($Path, (Get-ExOPNamespaceManager $Node))
    if ($null -ne $value) { return $value.InnerText }
    return ''
}

function ConvertTo-ExOPInstant {
    param (
        [Parameter(Mandatory)]
        [string]
        $Value
    )
    [DateTimeOffset]::Parse($Value, [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal).ToUniversalTime()
}

function Format-ExOPInstant {
    param (
        [DateTimeOffset]
        $Value
    )
    $Value.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', [Globalization.CultureInfo]::InvariantCulture)
}

function New-ExOPCalendarSession {
    <#
    .SYNOPSIS
        Creates an EWS connection configuration without contacting Exchange.
    .DESCRIPTION
        Run in regular Windows PowerShell on a user or management computer.
        Local elevation is not required. Credentials remain in memory.
    .PARAMETER EwsUrl
        HTTPS EWS endpoint with a certificate trusted by the client.
    .PARAMETER Credential
        Optional credential. If omitted, requests use the current Windows credentials.
    .PARAMETER Impersonation
        Uses ExchangeImpersonation for the explicitly requested mailbox.
        The account must already have appropriately scoped permissions.
    #>
    [CmdletBinding()]
    [OutputType('ExOP.CalendarSession')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates only an in-memory connection description; performs no I/O.')]
    param (
        [Parameter(Mandatory)]
        [uri]
        $EwsUrl,

        [PSCredential]
        $Credential,

        [switch]
        $Impersonation,

        [ValidateRange(10, 300)]
        [int]
        $TimeoutSeconds = 60,

        [string]
        $EwsUrlSource = 'Parameter'
    )
    if ($EwsUrl.Scheme -ne 'https' -or $EwsUrl.UserInfo) {
        throw 'EwsUrl must be HTTPS and must not contain embedded credentials.'
    }
    [PSCustomObject]@{
        PSTypeName                  ='ExOP.CalendarSession'
        EwsUrl                      =$EwsUrl
        EwsUrlSource                =$EwsUrlSource
        Credential                  =$Credential
        Impersonation               =[bool]$Impersonation
        TimeoutSeconds              =$TimeoutSeconds
        ReadOperations              =0
        WriteOperations             =0
        Diagnostics                 =(New-Object 'System.Collections.Generic.List[object]')
        ActiveOperation             =$null
        LastServerVersion           =''
        LastFrontEndServer          =''
        LastBackEndServer           =''
        ReadConnectionGroup         =[Guid]::NewGuid().ToString('N')
        ThrottlingRetries           =0
        ThrottlingDelayMilliseconds =[long]0
        SendPermissions             =@{}
    }
}

function ConvertFrom-ExOPXmlContent {
    param (
        [Parameter(Mandatory)]
        [string]
        $Content
    )
    $settings = New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $stringReader = New-Object IO.StringReader($Content)
    $xmlReader = [Xml.XmlReader]::Create($stringReader, $settings)
    $document = New-Object Xml.XmlDocument
    $document.XmlResolver = $null
    try { $document.Load($xmlReader) } finally { $xmlReader.Dispose(); $stringReader.Dispose() }
    return , $document
}

function Get-ExOPAutodiscoverScpRecord {
    <#
    .SYNOPSIS
        Reads the Exchange Autodiscover service connection points from Active Directory.
    .DESCRIPTION
        Works only on a domain-joined computer that can reach a domain controller. Returns nothing otherwise.
    #>
    [CmdletBinding()]
    param ()
    try {
        $rootDse = New-Object DirectoryServices.DirectoryEntry('LDAP://RootDSE')
        $configurationContext = [string]$rootDse.Properties['configurationNamingContext'].Value
        if (-not $configurationContext) { return }
        $searchRoot = New-Object DirectoryServices.DirectoryEntry("LDAP://$configurationContext")
        # 77378F46-... is the keyword Exchange stamps on Autodiscover URL service connection points.
        $searcher = New-Object DirectoryServices.DirectorySearcher($searchRoot,
            '(&(objectClass=serviceConnectionPoint)(keywords=77378F46-2C66-4aa9-A6A6-3E7A48B19596))',
            [string[]]@('serviceBindingInformation', 'keywords'))
        $searcher.PageSize = 100
        $results = $searcher.FindAll()
        try {
            foreach ($result in $results) {
                foreach ($url in @($result.Properties['servicebindinginformation'])) {
                    [PSCustomObject]@{ Url = [string]$url; Keywords = @($result.Properties['keywords'] | ForEach-Object { [string]$_ }) }
                }
            }
        } finally { $results.Dispose() }
    } catch {
        Write-Verbose "Autodiscover SCP lookup is not available: $($_.Exception.Message)"
    }
}

function Get-ExOPComputerSiteName {
    try { [DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name } catch { '' }
}

function Select-ExOPAutodiscoverScpUrl {
    <#
    .SYNOPSIS
        Orders SCP URLs like Outlook: the computer's site first, then SCPs without a site, then the rest.
    #>
    param (
        [object[]]
        $Records,

        [string]
        $SiteName
    )
    $index = 0
    $ranked = foreach ($record in @($Records | Where-Object { $null -ne $_ })) {
        $sites = @($record.Keywords | Where-Object { $_ -like 'Site=*' } | ForEach-Object { $_.Substring(5) })
        $rank = if ($SiteName -and $sites -contains $SiteName) { 0 } elseif ($sites.Count -eq 0) { 1 } else { 2 }
        [PSCustomObject]@{ Url = $record.Url; Rank = $rank; Index = $index++ }
    }
    $seen = @{}
    foreach ($entry in @($ranked | Sort-Object -Property Rank, Index)) {
        $uri = $null
        if (-not [Uri]::TryCreate($entry.Url, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -ne 'https') { continue }
        if ($seen.ContainsKey($uri.AbsoluteUri.ToLowerInvariant())) { continue }
        $seen[$uri.AbsoluteUri.ToLowerInvariant()] = $true
        $uri.AbsoluteUri
    }
}

function New-ExOPIntegratedCredentialCache {
    <#
        Offers an explicit credential only for Negotiate and NTLM, so it is never sent with Basic authentication.
        Used for Autodiscover and for EWS URLs that were found by Autodiscover rather than given by the administrator.
    #>
    [CmdletBinding()]
    [OutputType([Net.CredentialCache])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates an in-memory credential cache; performs no I/O.')]
    param (
        [Parameter(Mandatory)]
        [uri]
        $Url,

        [Parameter(Mandatory)]
        [PSCredential]
        $Credential
    )
    $cache = New-Object Net.CredentialCache
    $prefix = New-Object Uri($Url.GetLeftPart([UriPartial]::Authority))
    $cache.Add($prefix, 'Negotiate', $Credential.GetNetworkCredential())
    $cache.Add($prefix, 'NTLM', $Credential.GetNetworkCredential())
    # CredentialCache is enumerable; -NoEnumerate returns the cache itself.
    Write-Output -InputObject $cache -NoEnumerate
}

function Invoke-ExOPAutodiscoverRequest {
    <#
    .SYNOPSIS
        Sends one POX Autodiscover request. HTTP redirects are not followed.
    #>
    [CmdletBinding()]
    [OutputType([Xml.XmlDocument])]
    param (
        [Parameter(Mandatory)]
        [uri]
        $Url,

        [Parameter(Mandatory)]
        [string]
        $EmailAddress,

        [PSCredential]
        $Credential,

        [int]
        $TimeoutSeconds = 30
    )
    if ($Url.Scheme -ne 'https' -or $Url.UserInfo) { throw "Autodiscover URL '$Url' is not an HTTPS URL without embedded credentials." }
    $body = '<?xml version="1.0" encoding="utf-8"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">' +
    '<Request><EMailAddress>' + (ConvertTo-ExOPXmlText $EmailAddress) + '</EMailAddress>' +
    '<AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>'
    $bytes = [Text.Encoding]::UTF8.GetBytes($body)
    $request = [Net.HttpWebRequest]::Create($Url)
    $request.Method = 'POST'
    $request.ContentType = 'text/xml; charset=utf-8'
    $request.Timeout = $TimeoutSeconds * 1000
    $request.ReadWriteTimeout = $TimeoutSeconds * 1000
    $request.AllowAutoRedirect = $false
    $request.ContentLength = $bytes.Length
    if ($null -ne $Credential) {
        # Integrated authentication only: an explicit password is never sent with Basic to an Autodiscover host.
        $request.Credentials = New-ExOPIntegratedCredentialCache -Url $Url -Credential $Credential
    } else { $request.UseDefaultCredentials = $true }
    $response = $null
    try {
        $stream = $request.GetRequestStream()
        try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
        $response = $request.GetResponse()
        $status = [int]$response.StatusCode
        if ($status -ne 200) { throw "HTTP $status (redirects are not followed)" }
        $reader = New-Object IO.StreamReader($response.GetResponseStream(), [Text.Encoding]::UTF8)
        try { $content = $reader.ReadToEnd() } finally { $reader.Dispose() }
        ConvertFrom-ExOPXmlContent -Content $content
    } finally {
        if ($null -ne $response) { $response.Dispose() }
    }
}

function Get-ExOPAutodiscoverResult {
    <#
    .SYNOPSIS
        Interprets a POX Autodiscover response.
    .PARAMETER Preference
        Internal returns the EXCH (internal) EWS URL first; External returns the EXPR (external) URL first.
    #>
    param (
        [Parameter(Mandatory)]
        [Xml.XmlDocument]
        $Document,

        [ValidateSet('Internal', 'External')]
        [string]
        $Preference = 'Internal'
    )
    $errorNode = $Document.SelectSingleNode("//*[local-name()='Response']/*[local-name()='Error']")
    if ($null -ne $errorNode) {
        throw ('Autodiscover error {0}: {1}' -f (Get-ExOPText $errorNode "*[local-name()='ErrorCode']"), (Get-ExOPText $errorNode "*[local-name()='Message']"))
    }
    $account = $Document.SelectSingleNode("//*[local-name()='Response']/*[local-name()='Account']")
    if ($null -eq $account) { throw 'The Autodiscover response contains no account settings.' }
    $action = Get-ExOPText $account "*[local-name()='Action']"
    switch ($action) {
        'redirectAddr' { return [PSCustomObject]@{ Action = $action; Target = (Get-ExOPText $account "*[local-name()='RedirectAddr']"); EwsUrl = ''; ProtocolType = '' } }
        'redirectUrl' { return [PSCustomObject]@{ Action = $action; Target = (Get-ExOPText $account "*[local-name()='RedirectUrl']"); EwsUrl = ''; ProtocolType = '' } }
        'settings' { }
        default { throw "Unsupported Autodiscover action '$action'." }
    }
    $order = if ($Preference -eq 'Internal') { 'EXCH', 'EXPR' } else { 'EXPR', 'EXCH' }
    foreach ($type in $order) {
        foreach ($protocol in @($account.SelectNodes("*[local-name()='Protocol']"))) {
            if ((Get-ExOPText $protocol "*[local-name()='Type']") -ne $type) { continue }
            $value = Get-ExOPText $protocol "*[local-name()='EwsUrl']"
            $uri = $null
            if ($value -and [Uri]::TryCreate($value, [UriKind]::Absolute, [ref]$uri) -and $uri.Scheme -eq 'https' -and -not $uri.UserInfo) {
                return [PSCustomObject]@{ Action = $action; Target = ''; EwsUrl = $uri.AbsoluteUri; ProtocolType = $type }
            }
        }
    }
    throw 'The Autodiscover response contains no HTTPS EWS URL.'
}

function Resolve-ExOPEwsUrl {
    <#
    .SYNOPSIS
        Finds the EWS URL of a mailbox with Autodiscover.
    .DESCRIPTION
        Tries the Active Directory SCP first (internal EWS URL preferred), then
        https://<domain>/autodiscover/autodiscover.xml and https://autodiscover.<domain>/autodiscover/autodiscover.xml
        (external EWS URL preferred). Follows address redirects only; HTTP and URL redirects are not followed.
        Certificates are validated normally.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $EmailAddress,

        [PSCredential]
        $Credential
    )
    $attempts = New-Object 'System.Collections.Generic.List[string]'
    $scpUrls = @(Select-ExOPAutodiscoverScpUrl -Records @(Get-ExOPAutodiscoverScpRecord) -SiteName (Get-ExOPComputerSiteName))
    $visited = @{}
    $address = $EmailAddress.Trim()
    if ($address -notmatch '^[^@\s]+@([^@\s]+\.[^@\s]+)$') { throw "'$address' is not a valid SMTP address for Autodiscover." }
    $originalDomain = $Matches[1].ToLowerInvariant()
    $maximumHops = 3
    for ($hop = 0; $hop -lt $maximumHops; $hop++) {
        if ($address -notmatch '^[^@\s]+@([^@\s]+\.[^@\s]+)$') { throw "'$address' is not a valid SMTP address for Autodiscover." }
        $domain = $Matches[1]
        $visited[$address.ToLowerInvariant()] = $true
        $candidates = @(
            foreach ($url in $scpUrls) { [PSCustomObject]@{ Url = $url; Source = 'SCP'; Preference = 'Internal' } }
            # After a redirect to another domain only the Active Directory SCP endpoints are trusted.
            if ($domain.ToLowerInvariant() -eq $originalDomain) {
                [PSCustomObject]@{ Url = "https://$domain/autodiscover/autodiscover.xml"; Source = 'DNS'; Preference = 'External' }
                [PSCustomObject]@{ Url = "https://autodiscover.$domain/autodiscover/autodiscover.xml"; Source = 'DNS'; Preference = 'External' }
            } else {
                $attempts.Add("DNS endpoints of $domain are not used after a redirect from $originalDomain")
            }
        )
        $redirect = $null
        foreach ($candidate in $candidates) {
            try {
                $document = Invoke-ExOPAutodiscoverRequest -Url $candidate.Url -EmailAddress $address -Credential $Credential
                $result = Get-ExOPAutodiscoverResult -Document $document -Preference $candidate.Preference
            } catch {
                $attempts.Add("$($candidate.Url): $($_.Exception.Message)")
                continue
            }
            if ($result.Action -eq 'settings') {
                $ewsHost = ([uri]$result.EwsUrl).Host.ToLowerInvariant()
                $domainLower = $domain.ToLowerInvariant()
                # DNS-based Autodiscover answers are only trusted for an EWS host inside the mailbox domain;
                # the Active Directory SCP is trusted as published by Exchange.
                if ($candidate.Source -eq 'DNS' -and $ewsHost -ne $domainLower -and -not $ewsHost.EndsWith('.' + $domainLower)) {
                    $attempts.Add("$($candidate.Url): EWS URL host '$ewsHost' is outside '$domainLower' and was not used")
                    continue
                }
                return [PSCustomObject]@{
                    EwsUrl          = [uri]$result.EwsUrl
                    EmailAddress    = $address
                    AutodiscoverUrl = $candidate.Url
                    Source          = "Autodiscover $($candidate.Source) $($candidate.Url) ($($result.ProtocolType))"
                }
            }
            if ($result.Action -eq 'redirectAddr' -and $result.Target) { $redirect = $result.Target; break }
            $attempts.Add("$($candidate.Url): $($result.Action) to '$($result.Target)' is not followed")
        }
        if (-not $redirect) { break }
        if ($visited.ContainsKey($redirect.ToLowerInvariant())) { $attempts.Add("Redirect loop at $redirect"); break }
        $attempts.Add("$address redirected to $redirect")
        if ($hop + 1 -ge $maximumHops) { $attempts.Add("Stopped after $maximumHops addresses"); break }
        Write-Verbose "Autodiscover redirected $address to $redirect"
        $address = $redirect
    }
    throw ("Autodiscover could not find the EWS URL for $EmailAddress. Specify -EwsUrl. Attempts:`n  " + ($attempts -join "`n  "))
}

function Get-ExOPSessionEwsUrlSource {
    param (
        [Parameter(Mandatory)]
        $Session
    )
    if ($null -ne $Session.PSObject.Properties['EwsUrlSource'] -and $Session.EwsUrlSource) { return [string]$Session.EwsUrlSource }
    'Parameter'
}

function Get-ExOPCurrentUserSmtpAddress {
    try {
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $searcher = New-Object DirectoryServices.DirectorySearcher("(objectSid=$sid)", [string[]]@('mail'))
        $result = $searcher.FindOne()
        if ($null -ne $result) { return [string]($result.Properties['mail'] | Select-Object -First 1) }
    } catch {
        Write-Verbose "The current user's SMTP address could not be read from Active Directory: $($_.Exception.Message)"
    }
    ''
}

$script:SendAsRightGuid = [Guid]'ab721a54-1e2f-11d0-9819-00aa0040529b'
# Send-As ACEs inherited from a container apply to these object classes (user, inetOrgPerson) or to all classes.
$script:SendAsTargetClassGuids = @([Guid]::Empty, [Guid]'bf967aba-0de6-11d0-a285-00aa003049e2', [Guid]'4828cc14-1437-45bc-9b07-ad6f015e5f28')

function Get-ExOPDirectoryEntry {
    param (
        [string]
        $Path,

        [PSCredential]
        $Credential
    )
    if ($null -eq $Credential) { return New-Object DirectoryServices.DirectoryEntry($Path) }
    New-Object DirectoryServices.DirectoryEntry($Path, $Credential.UserName, $Credential.GetNetworkCredential().Password)
}

function Find-ExOPDirectoryObject {
    param (
        [string]
        $Filter,

        [PSCredential]
        $Credential
    )
    $rootDse = Get-ExOPDirectoryEntry -Path 'LDAP://RootDSE' -Credential $Credential
    $forest = [string]$rootDse.psbase.Properties['rootDomainNamingContext'].Value
    $searcher = New-Object DirectoryServices.DirectorySearcher((Get-ExOPDirectoryEntry -Path "GC://$forest" -Credential $Credential), $Filter, [string[]]@('distinguishedName'))
    $found = @($searcher.FindAll())
    if ($found.Count -ne 1) { throw "Active Directory returned $($found.Count) objects for $Filter." }
    [string]$found[0].Properties['distinguishedName'][0]
}

function ConvertTo-ExOPLdapFilterValue {
    param (
        [string]
        $Value
    )
    $builder = New-Object Text.StringBuilder
    foreach ($character in $Value.ToCharArray()) {
        if ($character -in '*', '(', ')', '\', [char]0) { [void]$builder.AppendFormat('\{0:x2}', [int]$character) } else { [void]$builder.Append($character) }
    }
    $builder.ToString()
}

function Get-ExOPCredentialAccountFilter {
    <#
        LDAP filter for the account of an explicit credential. sAMAccountName is unique only within a domain, so a
        DOMAIN\user name is resolved to its SID first; the forest-wide name search is only the fallback.
    #>
    param (
        [string]
        $UserName
    )
    if ($UserName -like '*@*') { return "(userPrincipalName=$(ConvertTo-ExOPLdapFilterValue $UserName))" }
    if ($UserName -like '*\*') {
        try {
            $sid = (New-Object Security.Principal.NTAccount($UserName)).Translate([Security.Principal.SecurityIdentifier]).Value
            return "(objectSid=$sid)"
        } catch {
            Write-Verbose "The account $UserName could not be resolved to a SID: $($_.Exception.Message)"
        }
    }
    "(&(objectCategory=person)(sAMAccountName=$(ConvertTo-ExOPLdapFilterValue ($UserName -replace '^.*\\', ''))))"
}

function Get-ExOPCallerIdentity {
    <#
    .SYNOPSIS
        Returns the SID and security group SIDs of the account that authenticates to EWS.
    #>
    param (
        [PSCredential]
        $Credential
    )
    if ($null -eq $Credential) {
        $current = [Security.Principal.WindowsIdentity]::GetCurrent()
        return [PSCustomObject]@{
            Name = $current.Name; Sid = $current.User.Value
            GroupSids = @($current.Groups | ForEach-Object { $_.Translate([Security.Principal.SecurityIdentifier]).Value })
        }
    }
    $name = $Credential.UserName
    $filter = Get-ExOPCredentialAccountFilter -UserName $name
    $entry = Get-ExOPDirectoryEntry -Path ('LDAP://' + (Find-ExOPDirectoryObject -Filter $filter -Credential $Credential)) -Credential $Credential
    $entry.RefreshCache([string[]]@('objectSid', 'tokenGroups'))
    [PSCustomObject]@{
        Name      = $name
        Sid       = (New-Object Security.Principal.SecurityIdentifier([byte[]]$entry.psbase.Properties['objectSid'].Value, 0)).Value
        GroupSids = @($entry.psbase.Properties['tokenGroups'] | ForEach-Object { (New-Object Security.Principal.SecurityIdentifier([byte[]]$_, 0)).Value })
    }
}

function ConvertFrom-ExOPSendAsRules {
    <#
    .SYNOPSIS
        Reduces a mailbox owner's access rules to the entries that grant or deny Send As on the object itself.
    #>
    param (
        [object[]]
        $Rules
    )
    foreach ($rule in $Rules) {
        if (($rule.ActiveDirectoryRights -band ([DirectoryServices.ActiveDirectoryRights]::ExtendedRight)) -eq 0) { continue }
        if ($rule.ObjectType -ne [Guid]::Empty -and $rule.ObjectType -ne $script:SendAsRightGuid) { continue }
        if ($rule.IsInherited -and $script:SendAsTargetClassGuids -notcontains $rule.InheritedObjectType) { continue }
        if (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
        [PSCustomObject]@{
            Sid = $rule.IdentityReference.Value; Allow = $rule.AccessControlType -eq 'Allow'; Inherited = [bool]$rule.IsInherited
        }
    }
}

function Get-ExOPMailboxSendRights {
    <#
    .SYNOPSIS
        Reads the owner's SIDs, Send on Behalf delegates (publicDelegates) and Send As entries from Active Directory.
    #>
    param (
        [string]
        $Mailbox,

        [PSCredential]
        $Credential
    )
    $distinguishedName = Find-ExOPDirectoryObject -Filter "(proxyAddresses=smtp:$(ConvertTo-ExOPLdapFilterValue $Mailbox))" -Credential $Credential
    $entry = Get-ExOPDirectoryEntry -Path "LDAP://$distinguishedName" -Credential $Credential
    $entry.psbase.Options.SecurityMasks = [DirectoryServices.SecurityMasks]::Dacl
    $entry.RefreshCache([string[]]@('objectSid', 'msExchMasterAccountSid', 'publicDelegates', 'nTSecurityDescriptor'))
    $toSid = { param($bytes) (New-Object Security.Principal.SecurityIdentifier([byte[]]$bytes, 0)).Value }
    $delegateSids = @(
        foreach ($delegate in @($entry.psbase.Properties['publicDelegates'])) {
            $delegateEntry = Get-ExOPDirectoryEntry -Path "LDAP://$delegate" -Credential $Credential
            $delegateEntry.RefreshCache([string[]]@('objectSid'))
            & $toSid $delegateEntry.psbase.Properties['objectSid'].Value
        }
    )
    [PSCustomObject]@{
        Sid          = & $toSid $entry.psbase.Properties['objectSid'].Value
        MasterSid    = if ($entry.psbase.Properties['msExchMasterAccountSid'].Count -gt 0) { & $toSid $entry.psbase.Properties['msExchMasterAccountSid'].Value } else { '' }
        DelegateSids = $delegateSids
        SendAs       = @(ConvertFrom-ExOPSendAsRules -Rules @($entry.psbase.ObjectSecurity.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])))
    }
}

function Resolve-ExOPSendPermission {
    <#
    .SYNOPSIS
        Decides how Exchange would let the caller send for the owner: Owner, SendAs, SendOnBehalf or None.
    #>
    param (
        $Caller,

        $Owner
    )
    if ($Caller.Sid -eq $Owner.Sid -or ($Owner.MasterSid -and $Caller.Sid -eq $Owner.MasterSid)) { return 'Owner' }
    $sids = New-Object 'System.Collections.Generic.HashSet[string]'([StringComparer]::OrdinalIgnoreCase)
    foreach ($sid in @($Caller.Sid) + @($Caller.GroupSids) + @('S-1-1-0', 'S-1-5-11')) { if ($sid) { [void]$sids.Add($sid) } }
    # Canonical ACL order: explicit entries before inherited ones, and deny before allow within each group.
    foreach ($inherited in $false, $true) {
        $matching = @($Owner.SendAs | Where-Object { $_.Inherited -eq $inherited -and $sids.Contains($_.Sid) })
        if (@($matching | Where-Object { -not $_.Allow }).Count -gt 0) { break }
        if (@($matching | Where-Object { $_.Allow }).Count -gt 0) { return 'SendAs' }
    }
    if (@($Owner.DelegateSids | Where-Object { $sids.Contains($_) }).Count -gt 0) { return 'SendOnBehalf' }
    'None'
}

function Get-ExOPSendPermission {
    <#
    .SYNOPSIS
        Returns how the EWS account may send meeting updates for a mailbox. Results are cached in the session.
    .DESCRIPTION
        Exchange does not check Send on Behalf for meeting messages that a delegate sends from the owner's
        calendar, so the script checks it itself before changing anything. Mode is Impersonation, Owner, SendAs,
        SendOnBehalf, None, or Unknown when Active Directory could not be read.
    #>
    param (
        [Parameter(Mandatory)]
        $Session,

        [Parameter(Mandatory)]
        [string]
        $Mailbox
    )
    if ($Session.Impersonation) { return [PSCustomObject]@{ Mode = 'Impersonation'; Error = '' } }
    if ($null -eq $Session.PSObject.Properties['SendPermissions']) {
        $Session | Add-Member -NotePropertyName SendPermissions -NotePropertyValue @{}
    }
    $key = $Mailbox.ToLowerInvariant()
    if (-not $Session.SendPermissions.ContainsKey($key)) {
        $Session.SendPermissions[$key] = try {
            $caller = Get-ExOPCallerIdentity -Credential $Session.Credential
            $owner = Get-ExOPMailboxSendRights -Mailbox $Mailbox -Credential $Session.Credential
            [PSCustomObject]@{ Mode = (Resolve-ExOPSendPermission -Caller $caller -Owner $owner); Error = '' }
        } catch {
            [PSCustomObject]@{ Mode = 'Unknown'; Error = $_.Exception.Message }
        }
    }
    $Session.SendPermissions[$key]
}

function Assert-ExOPSendPermission {
    <#
    .SYNOPSIS
        Stops before any change when the caller is a delegate without Send on Behalf or Send As.
    #>
    param (
        [Parameter(Mandatory)]
        $Session,

        [Parameter(Mandatory)]
        [string]
        $Mailbox,

        [switch]
        $SkipSendPermissionCheck
    )
    if ($SkipSendPermissionCheck) { return }
    $permission = Get-ExOPSendPermission -Session $Session -Mailbox $Mailbox
    if ($permission.Mode -notin 'None', 'Unknown') { return }
    $reason = if ($permission.Mode -eq 'None') {
        "The account running the script has neither Send on Behalf nor Send As for $Mailbox."
    } else {
        "The Send on Behalf and Send As permissions for $Mailbox could not be checked in Active Directory: $($permission.Error)"
    }
    $exception = New-Object InvalidOperationException ($reason + ' Exchange would still send the meeting updates on behalf of the organizer. ' +
        'Grant Send on Behalf or Send As, run the script as the mailbox owner, use -Impersonation, or add -SkipSendPermissionCheck to allow it. Nothing was changed.')
    $exception.Data['EwsResponseCode'] = if ($permission.Mode -eq 'None') { 'SendPermissionMissing' } else { 'SendPermissionUnknown' }
    throw $exception
}

function Invoke-ExOPEwsRequest {
    [CmdletBinding()]
    [OutputType([Xml.XmlDocument])]
    param (
        [Parameter(Mandatory)]
        $Session,

        [Parameter(Mandatory)]
        [string]
        $Body,

        [string]
        $Mailbox,

        [switch]
        $ReadOnly,

        [string]
        $TimeZoneContextId = 'UTC'
    )
    $impersonationHeader=''
    if ($Session.Impersonation -and $Mailbox) {
        $impersonationHeader='<t:ExchangeImpersonation><t:ConnectingSID><t:PrimarySmtpAddress>' +
        (ConvertTo-ExOPXmlText $Mailbox) + '</t:PrimarySmtpAddress></t:ConnectingSID></t:ExchangeImpersonation>'
    }
    $envelope='<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:t="' +
    $script:TypesNamespace + '" xmlns:m="' + $script:MessagesNamespace +
    '"><s:Header><t:RequestServerVersion Version="Exchange2013_SP1"/>' + $impersonationHeader +
    '<t:TimeZoneContext><t:TimeZoneDefinition Id="'+(ConvertTo-ExOPXmlText $TimeZoneContextId)+'"/></t:TimeZoneContext></s:Header><s:Body>' +
    $Body + '</s:Body></s:Envelope>'
    $bytes=[Text.Encoding]::UTF8.GetBytes($envelope)
    for ($attempt=0; ; $attempt++) {
        $request=[Net.HttpWebRequest]::Create($Session.EwsUrl)
        $request.Method='POST'
        $request.ContentType='text/xml; charset=utf-8'
        $request.Timeout=$Session.TimeoutSeconds*1000
        $request.ReadWriteTimeout=$Session.TimeoutSeconds*1000
        $request.AllowAutoRedirect=$false
        $request.ContentLength=$bytes.Length
        # Reads reuse one authenticated connection. Writes always use a new connection, so a stale
        # keep-alive connection can never make the outcome of a calendar change ambiguous.
        $request.ConnectionGroupName=if ($ReadOnly) { $Session.ReadConnectionGroup } else { [Guid]::NewGuid().ToString('N') }
        $request.KeepAlive=[bool]$ReadOnly
        if ($Mailbox) { $request.Headers['X-AnchorMailbox'] = $Mailbox }
        if ($null -ne $Session.Credential) {
            # A URL found by Autodiscover was not chosen by the administrator: never offer the password with Basic there.
            $request.Credentials = if ((Get-ExOPSessionEwsUrlSource -Session $Session) -ne 'Parameter') {
                New-ExOPIntegratedCredentialCache -Url $Session.EwsUrl -Credential $Session.Credential
            } else { $Session.Credential.GetNetworkCredential() }
        } else { $request.UseDefaultCredentials=$true }
        if ($ReadOnly) { $Session.ReadOperations++ } else { $Session.WriteOperations++ }
        $response=$null
        $retryMilliseconds=$null
        try {
            $stream=$request.GetRequestStream()
            try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
            try { $response=$request.GetResponse() }
            catch [Net.WebException] {
                if ($null -eq $_.Exception.Response) { throw }
                $response=$_.Exception.Response
                $status=[int]$response.StatusCode
                # An HTTP-level 429/503 does not prove that a write was not executed; only reads are retried.
                if ($ReadOnly -and $status -in @(429, 503)) {
                    $retryAfter=0
                    $retryMilliseconds=if ([int]::TryParse([string]$response.Headers['Retry-After'], [ref]$retryAfter)) { $retryAfter*1000 } else { 0 }
                } elseif ($status -ne 500) { throw }
            }
            if ($null -ne $retryMilliseconds) { $content=$null } else {
                $Session.LastFrontEndServer=[string]$response.Headers['X-FEServer']
                $Session.LastBackEndServer=[string]$response.Headers['X-BEServer']
                $reader=New-Object IO.StreamReader($response.GetResponseStream())
                try { $content=$reader.ReadToEnd() } finally { $reader.Dispose() }
            }
            if ($null -ne $content) {
                $settings=New-Object Xml.XmlReaderSettings
                $settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit
                $settings.XmlResolver=$null
                $stringReader=New-Object IO.StringReader($content)
                $xmlReader=[Xml.XmlReader]::Create($stringReader, $settings)
                $document=New-Object Xml.XmlDocument
                $document.XmlResolver=$null
                try { $document.Load($xmlReader) } finally { $xmlReader.Dispose(); $stringReader.Dispose() }
                $namespaces=Get-ExOPNamespaceManager $document
                $versionNode = $document.SelectSingleNode('//t:ServerVersionInfo', $namespaces)
                if ($null -ne $versionNode) {
                    $Session.LastServerVersion = @('MajorVersion', 'MinorVersion', 'MajorBuildNumber', 'MinorBuildNumber' |
                            ForEach-Object { $versionNode.GetAttribute($_) }) -join '.'
                }
                $fault=$document.SelectSingleNode('//s:Fault', $namespaces)
                if ($null -ne $fault) {
                    $faultCode=((Get-ExOPText $fault "*[local-name()='faultcode']") -split ':')[-1]
                    $faultMessage=Get-ExOPText $fault "*[local-name()='faultstring']"
                    $detailCode=Get-ExOPText $fault "*[local-name()='detail']/*[local-name()='ResponseCode']"
                    # Throttling is also returned as a SOAP fault; it is rejected before execution like the response-level code.
                    if ($faultCode -eq 'ErrorServerBusy' -or $detailCode -eq 'ErrorServerBusy') {
                        $retryMilliseconds=Get-ExOPServerBackOffMilliseconds -ErrorNode $fault
                    } else {
                        $exception=New-Object InvalidOperationException("EWS SOAP fault [$faultCode]: $faultMessage")
                        $exception.Data['EwsResponseCode']=if ($detailCode) { $detailCode } else { $faultCode }
                        throw $exception
                    }
                }
                $errorNode=if ($null -eq $retryMilliseconds) { $document.SelectSingleNode("//m:*[@ResponseClass='Error']", $namespaces) } else { $null }
                if ($null -ne $errorNode) {
                    $code=Get-ExOPText $errorNode 'm:ResponseCode'
                    $message=Get-ExOPText $errorNode 'm:MessageText'
                    # ErrorServerBusy is a throttling rejection returned before the request is executed,
                    # so it is retried for reads and writes after the server-provided back-off.
                    if ($code -eq 'ErrorServerBusy') {
                        $retryMilliseconds=Get-ExOPServerBackOffMilliseconds -ErrorNode $errorNode
                    } else {
                        $exception=New-Object InvalidOperationException("EWS [$code]: $message")
                        $exception.Data['EwsResponseCode']=$code
                        throw $exception
                    }
                }
                if ($null -eq $retryMilliseconds) {
                    $PSCmdlet.WriteObject($document, $false)
                    return
                }
            }
        } finally {
            if ($null -ne $response) { $response.Dispose() }
            if (-not $ReadOnly) { $null=$request.ServicePoint.CloseConnectionGroup($request.ConnectionGroupName) }
        }
        if ($attempt -ge $script:MAX_THROTTLING_RETRIES) {
            $exception=New-Object InvalidOperationException("EWS remained busy after $($script:MAX_THROTTLING_RETRIES) throttling retries.")
            $exception.Data['EwsResponseCode']='ErrorServerBusy'
            throw $exception
        }
        $delay=Get-ExOPRetryDelayMilliseconds -Attempt $attempt -ServerMilliseconds $retryMilliseconds
        $Session.ThrottlingRetries++
        $Session.ThrottlingDelayMilliseconds+=[long]$delay
        Start-Sleep -Milliseconds ([int]$delay)
    }
}

function Get-ExOPServerBackOffMilliseconds {
    param (
        [Parameter(Mandatory)]
        [Xml.XmlNode]
        $ErrorNode
    )
    $backOff = 0
    # Works for response-level errors (m:MessageXml) and SOAP fault details (detail/MessageXml).
    if ([int]::TryParse((Get-ExOPText -Node $ErrorNode -Path ".//*[local-name()='MessageXml']/*[local-name()='Value' and @Name='BackOffMilliseconds']"), [ref]$backOff) -and $backOff -gt 0) {
        return $backOff
    }
    0
}

function Get-ExOPRetryDelayMilliseconds {
    <#
        The larger of the server back-off and an exponential minimum (1, 2, 4, ... seconds), capped.
    #>
    param (
        [int]
        $Attempt,

        [AllowNull()]
        $ServerMilliseconds
    )
    $server = if ($null -eq $ServerMilliseconds) { 0.0 } else { [double]$ServerMilliseconds }
    [int][Math]::Min([Math]::Max($server, [Math]::Pow(2, $Attempt) * 1000), $script:MAX_BACKOFF_SECONDS * 1000)
}

function Get-ExOPCalendarTimeZone {
    <#
    .SYNOPSIS
        Lists Windows timezone IDs and display names supplied by EWS.
    .DESCRIPTION
        This read-only operation does not change mailbox or Windows settings.
        Use regular Windows PowerShell on the user or management computer; no elevation.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory)]
        $Session
    )
    $xml=Invoke-ExOPEwsRequest $Session '<m:GetServerTimeZones ReturnFullTimeZoneData="false"/>' -ReadOnly
    foreach ($zone in $xml.SelectNodes('//t:TimeZoneDefinition', (Get-ExOPNamespaceManager $xml))) {
        [PSCustomObject]@{Id=$zone.GetAttribute('Id'); DisplayName=$zone.GetAttribute('Name') }
    }
}

function Get-ExOPCalendarWindow {
    param (
        $Session,

        [string]
        $Mailbox,

        [DateTimeOffset]
        $Start,

        [DateTimeOffset]
        $End,

        [int]
        $Depth = 0,

        [int]
        $PageSize = 500
    )
    $body='<m:FindItem Traversal="Shallow"><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape><t:AdditionalProperties>' +
    '<t:FieldURI FieldURI="calendar:CalendarItemType"/><t:FieldURI FieldURI="calendar:Start"/>' +
    '<t:FieldURI FieldURI="calendar:End"/></t:AdditionalProperties></m:ItemShape>' +
    '<m:CalendarView StartDate="' + (Format-ExOPInstant $Start) + '" EndDate="' + (Format-ExOPInstant $End) +
    '" MaxEntriesReturned="' + $PageSize + '"/><m:ParentFolderIds><t:DistinguishedFolderId Id="calendar">' +
    '<t:Mailbox><t:EmailAddress>' + (ConvertTo-ExOPXmlText $Mailbox) +
    '</t:EmailAddress></t:Mailbox></t:DistinguishedFolderId></m:ParentFolderIds></m:FindItem>'
    $xml=Invoke-ExOPEwsRequest $Session $body -Mailbox $Mailbox -ReadOnly
    $root=$xml.SelectSingleNode('//m:RootFolder', (Get-ExOPNamespaceManager $xml))
    if ($null -eq $root -or -not $root.HasAttribute('IncludesLastItemInRange')) { throw 'EWS did not return calendar-view completeness information.' }
    if ($root.GetAttribute('IncludesLastItemInRange') -ne 'true') {
        if ($Depth -ge 30 -or ($End-$Start).TotalSeconds -le 1) {
            throw 'Calendar view remains truncated at the minimum query interval. No complete report can be produced.'
        }
        $middle=$Start.AddTicks([long](($End-$Start).Ticks/2))
        Get-ExOPCalendarWindow -Session $Session -Mailbox $Mailbox -Start $Start -End $middle -Depth ($Depth+1) -PageSize $PageSize
        Get-ExOPCalendarWindow -Session $Session -Mailbox $Mailbox -Start $middle -End $End -Depth ($Depth+1) -PageSize $PageSize
        return
    }
    foreach ($item in $root.SelectNodes('t:Items/t:CalendarItem', (Get-ExOPNamespaceManager $root))) { Write-Output -InputObject $item -NoEnumerate }
}

function Get-ExOPCalendarItems {
    param (
        $Session,

        [string]
        $Mailbox,

        [string[]]
        $References,

        [switch]
        $IdOnly
    )
    for ($offset=0; $offset -lt $References.Count; $offset+=50) {
        $last=[Math]::Min($offset+49, $References.Count-1)
        $properties=if ($IdOnly) { '<t:BaseShape>IdOnly</t:BaseShape>' }else {
            '<t:BaseShape>AllProperties</t:BaseShape><t:BodyType>HTML</t:BodyType><t:AdditionalProperties>' +
            '<t:FieldURI FieldURI="calendar:StartTimeZone"/><t:FieldURI FieldURI="calendar:EndTimeZone"/>' +
            '<t:FieldURI FieldURI="calendar:Recurrence"/><t:FieldURI FieldURI="calendar:ModifiedOccurrences"/>' +
            '<t:FieldURI FieldURI="calendar:DeletedOccurrences"/>' + $script:MigrationStateFieldUri +
            $script:MigrationReceiptFieldUri +
            '<t:ExtendedFieldURI DistinguishedPropertySetId="Common" PropertyId="34050" PropertyType="SystemTime"/>' +
            '<t:ExtendedFieldURI DistinguishedPropertySetId="Common" PropertyId="34144" PropertyType="SystemTime"/>' +
            '</t:AdditionalProperties>'
        }
        $body='<m:GetItem><m:ItemShape>'+$properties+'</m:ItemShape><m:ItemIds>'+
        ($References[$offset..$last] -join '')+'</m:ItemIds></m:GetItem>'
        $xml=Invoke-ExOPEwsRequest $Session $body -Mailbox $Mailbox -ReadOnly
        foreach ($item in $xml.SelectNodes('//m:GetItemResponseMessage/m:Items/t:CalendarItem', (Get-ExOPNamespaceManager $xml))) {
            Write-Output -InputObject $item -NoEnumerate
        }
    }
}

function Get-ExOPCalendarItem {
    param (
        $Session,

        [string]
        $Mailbox,

        [string]
        $ItemId,

        [string]
        $Reference
    )
    if (-not $Reference) { $Reference='<t:ItemId Id="'+(ConvertTo-ExOPXmlText $ItemId)+'"/>' }
    $items=@(Get-ExOPCalendarItems -Session $Session -Mailbox $Mailbox -References @($Reference))
    if ($items.Count -ne 1) { throw "Expected one calendar item, received $($items.Count)." }
    return , $items[0]
}

function Get-ExOPCalendarMigrationReport {
    <#
    .SYNOPSIS
        Finds organizer-owned events and whole recurring series in a timezone.
    .DESCRIPTION
        Reads only the specified owner's default Calendar. A series is returned
        once when an occurrence intersects the query window. Start and end zone
        IDs are matched independently. No calendar items are modified.
        Run in regular Windows PowerShell on the user or management computer;
        local elevation is not required.
    .PARAMETER Mailbox
        Calendar owner, including when the authenticated account is a delegate.
    .PARAMETER FromWindowsTimeZoneId
        Full source Windows timezone ID, not a numeric UTC offset.
    .PARAMETER QueryStartDate
        Query start instant. Defaults to UTC now. Supply an explicit offset.
    .PARAMETER QueryWindowInDays
        Query duration, from 1 through 1825 days. Defaults to 365.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory)]
        $Session,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Mailbox,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $FromWindowsTimeZoneId,

        [DateTimeOffset]
        $QueryStartDate = [DateTimeOffset]::UtcNow,

        [ValidateRange(1, 1825)]
        [int]
        $QueryWindowInDays = 365,

        [ValidateRange(1, 1000)]
        [int]
        $PageSize = 500
    )
    $available=@(Get-ExOPCalendarTimeZone $Session)
    $sourceZone = @($available | Where-Object Id -EQ $FromWindowsTimeZoneId)
    if ($sourceZone.Count -eq 0) { throw "EWS does not recognize source zone '$FromWindowsTimeZoneId'." }
    # Report rows carry the server's exact ID, not the caller's spelling.
    $FromWindowsTimeZoneId = [string]$sourceZone[0].Id
    $start=$QueryStartDate.ToUniversalTime()
    $end=$start.AddDays($QueryWindowInDays)
    # EWS rejects calendar views longer than two years (ErrorCalendarViewRangeTooBig); query in one-year slices.
    $view=@(
        for ($sliceStart = $start; $sliceStart -lt $end; $sliceStart = $sliceStart.AddDays(365)) {
            $sliceEnd = if ($sliceStart.AddDays(365) -lt $end) { $sliceStart.AddDays(365) } else { $end }
            Get-ExOPCalendarWindow -Session $Session -Mailbox $Mailbox -Start $sliceStart -End $sliceEnd -Depth 0 -PageSize $PageSize
        }
    )
    $seen=New-Object 'System.Collections.Generic.HashSet[string]'
    $unique=New-Object 'System.Collections.Generic.List[object]'
    foreach ($item in $view) {
        $id=$item.SelectSingleNode('t:ItemId', (Get-ExOPNamespaceManager $item)).GetAttribute('Id')
        if ($seen.Add($id)) { $unique.Add($item) }
    }
    $occurrences=@($unique | Where-Object { (Get-ExOPText $_ 't:CalendarItemType') -in @('Occurrence', 'Exception') })
    $occurrenceToMaster = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
    if ($occurrences.Count -gt 0) {
        $refs=@($occurrences | ForEach-Object {
                '<t:RecurringMasterItemId OccurrenceId="'+(ConvertTo-ExOPXmlText $_.SelectSingleNode('t:ItemId', (Get-ExOPNamespaceManager $_)).GetAttribute('Id'))+'"/>'
            })
        $masters=@(Get-ExOPCalendarItems -Session $Session -Mailbox $Mailbox -References $refs -IdOnly)
        if ($masters.Count -ne $occurrences.Count) { throw 'EWS master resolution returned an unexpected response count.' }
        for ($index=0; $index -lt $masters.Count; $index++) {
            $occurrenceId=$occurrences[$index].SelectSingleNode('t:ItemId', (Get-ExOPNamespaceManager $occurrences[$index])).GetAttribute('Id')
            $occurrenceToMaster[$occurrenceId]=$masters[$index].SelectSingleNode('t:ItemId', (Get-ExOPNamespaceManager $masters[$index])).GetAttribute('Id')
        }
    }
    $firstById = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    foreach ($item in $unique) {
        $id=$item.SelectSingleNode('t:ItemId', (Get-ExOPNamespaceManager $item)).GetAttribute('Id')
        if ($occurrenceToMaster.ContainsKey($id)) { $id=$occurrenceToMaster[$id] }
        $when=ConvertTo-ExOPInstant (Get-ExOPText $item 't:Start')
        if (-not $firstById.ContainsKey($id) -or $when -lt $firstById[$id].Start) {
            $firstById[$id]=[PSCustomObject]@{Start=$when; End=(ConvertTo-ExOPInstant (Get-ExOPText $item 't:End')) }
        }
    }
    if ($firstById.Count -eq 0) { return }
    $references=@($firstById.Keys | ForEach-Object { '<t:ItemId Id="'+(ConvertTo-ExOPXmlText $_)+'"/>' })
    $details=@(Get-ExOPCalendarItems -Session $Session -Mailbox $Mailbox -References $references)
    foreach ($item in $details) {
        $ns=Get-ExOPNamespaceManager $item
        $identifier=$item.SelectSingleNode('t:ItemId', $ns)
        $id=$identifier.GetAttribute('Id')
        if ((Get-ExOPText $item 't:IsOrganizer') -ne 'true') { continue }
        $migrationState = Get-ExOPMigrationState -Item $item
        $recoveryRequired = $null -ne $migrationState -and $migrationState.FromZone -eq $FromWindowsTimeZoneId
        if ($recoveryRequired) {
            Write-Warning "Migration $($migrationState.OperationId) is incomplete for item $id. Run the script with -Reconcile before retrying."
        }
        $startNode=$item.SelectSingleNode('t:StartTimeZone', $ns)
        $endNode=$item.SelectSingleNode('t:EndTimeZone', $ns)
        if ($null -eq $startNode -or $null -eq $endNode) {
            $Session.Diagnostics.Add([PSCustomObject]@{Mailbox=$Mailbox; ItemId=$id; Code='MissingTimeZone' })
            Write-Warning "Calendar item $id has no complete timezone information; it was not classified as a match."
            continue
        }
        $startZone=$startNode.GetAttribute('Id'); $endZone=$endNode.GetAttribute('Id')
        # Without Outlook time zone definitions EWS reports a pseudo zone such as tzone://Microsoft/Utc.
        if ($startZone -like 'tzone://*' -or $endZone -like 'tzone://*') {
            $Session.Diagnostics.Add([PSCustomObject]@{Mailbox=$Mailbox; ItemId=$id; Code='NoWindowsTimeZoneDefinition'; Subject=(Get-ExOPText $item 't:Subject') })
            Write-Warning "Calendar item $id has no Outlook time zone definition (EWS reports '$startZone'); it cannot be matched to a source time zone and is not migrated."
            continue
        }
        # Items created by Exchange Online or other clients can carry an IANA zone name such as Europe/Lisbon.
        if ($startZone -like '*/*' -or $endZone -like '*/*') {
            $Session.Diagnostics.Add([PSCustomObject]@{Mailbox=$Mailbox; ItemId=$id; Code='IanaTimeZone'; Subject=(Get-ExOPText $item 't:Subject') })
            Write-Warning "Calendar item $id uses the IANA time zone '$startZone'/'$endZone' instead of a Windows time zone; it is not migrated."
            continue
        }
        $matchStart=$startZone -eq $FromWindowsTimeZoneId; $matchEnd=$endZone -eq $FromWindowsTimeZoneId
        if (-not($matchStart -or $matchEnd -or $recoveryRequired)) { continue }
        $type=Get-ExOPText $item 't:CalendarItemType'
        if ($type -notin @('Single', 'RecurringMaster')) { throw "Unexpected resolved calendar type '$type'." }
        $recurrence=$item.SelectSingleNode('t:Recurrence', $ns)
        $pattern=''; $seriesStart=''; $seriesEnd=''
        if ($null -ne $recurrence) {
            $patternNode=$recurrence.FirstChild
            $pattern=$patternNode.LocalName+': '+(@($patternNode.ChildNodes | ForEach-Object { $_.LocalName+'='+$_.InnerText })-join '; ')
            $seriesStart=Get-ExOPText $recurrence 't:*/t:StartDate'
            $seriesEnd=Get-ExOPText $recurrence 't:*/t:EndDate'
            if ($null -ne $recurrence.SelectSingleNode('t:NoEndRecurrence', $ns)) { $seriesEnd='NoEnd' }
            elseif (-not $seriesEnd) { $seriesEnd='Count:'+(Get-ExOPText $recurrence 't:*/t:NumberOfOccurrences') }
        }
        $rooms = Get-ExOPRoomInfo -Item $item
        [PSCustomObject][ordered]@{
            SchemaVersion='1'; Mailbox=$Mailbox; RecordType=if ($type -eq 'Single') { 'Single' }else { 'RecurringSeries' }
            Subject                 =(Get-ExOPText $item 't:Subject')
            Organizer               =(Get-ExOPText $item 't:Organizer/t:Mailbox/t:EmailAddress')
            StartTimeZoneId=$startZone; EndTimeZoneId=$endZone
            MatchedEndpoint         =if ($matchStart -and $matchEnd) { 'Both' }elseif ($matchStart) { 'Start' }elseif ($matchEnd) { 'End' }else { 'Recovery' }
            QueryStartUtc=(Format-ExOPInstant $start); QueryEndUtc=(Format-ExOPInstant $end)
            FirstOccurrenceStartUtc =(Format-ExOPInstant $firstById[$id].Start)
            FirstOccurrenceEndUtc   =(Format-ExOPInstant $firstById[$id].End)
            StartUtc                =(Format-ExOPInstant (ConvertTo-ExOPInstant (Get-ExOPText $item 't:Start')))
            EndUtc                  =(Format-ExOPInstant (ConvertTo-ExOPInstant (Get-ExOPText $item 't:End')))
            IsAllDay                =((Get-ExOPText $item 't:IsAllDayEvent') -eq 'true')
            IsCancelled             =((Get-ExOPText $item 't:IsCancelled') -eq 'true')
            HasRoom                 =$rooms.HasRoom
            RoomNames               =$rooms.RoomNames
            RoomSmtpAddresses       =$rooms.RoomSmtpAddresses
            SeriesStartDate=$seriesStart; SeriesEndDate=$seriesEnd; RecurrencePattern=$pattern
            ModifiedExceptionCount  =$item.SelectNodes('t:ModifiedOccurrences/t:Occurrence', $ns).Count
            DeletedExceptionCount   =$item.SelectNodes('t:DeletedOccurrences/t:DeletedOccurrence', $ns).Count
            FromWindowsTimeZoneId   =$FromWindowsTimeZoneId
            MigrationStatus         =if ($recoveryRequired) { 'RecoveryRequired' }else { 'None' }
            MigrationOperationId    =if ($recoveryRequired) { $migrationState.OperationId }else { '' }
            ItemId=$id; ChangeKey=$identifier.GetAttribute('ChangeKey')
            UID                     =(Get-ExOPText $item 't:UID')
        }
    }
}

function Resolve-ExOPFileSystemPath {
    <#
        .NET file APIs resolve relative paths against the process directory, which Set-Location does not change.
        Resolve user paths against the current PowerShell location instead.
    #>
    param (
        [Parameter(Mandatory)]
        [string]
        $Path
    )
    $provider = $null
    $drive = $null
    $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path, [ref]$provider, [ref]$drive)
    if ($provider.Name -ne 'FileSystem') { throw "The path '$Path' is not a file system path." }
    $resolved
}

function Export-ExOPCalendarMigrationReport {
    <#
    .SYNOPSIS
        Writes report objects to a UTF-8 CSV with a BOM.
    .DESCRIPTION
        Run in regular Windows PowerShell on the user or management computer.
        No elevation is required. This writes a local file, not calendar items.
        Formula-like display text is escaped without changing technical IDs.
    .PARAMETER Force
        Allows replacement of an existing output CSV.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        $InputObject,

        [Parameter(Mandatory)]
        [string]
        $Path,

        [switch]
        $Force
    )
    begin {
        $outputPath = Resolve-ExOPFileSystemPath -Path $Path
        if ((Test-Path -LiteralPath $outputPath) -and -not $Force) { throw "Output already exists: $outputPath. Use -Force explicitly to replace it." }
        $rows=New-Object 'System.Collections.Generic.List[object]'
    }
    process {
        foreach ($entry in @($InputObject)) {
            $copy=$entry | Select-Object *
            foreach ($property in 'Subject', 'Organizer', 'RecurrencePattern', 'RoomNames', 'RoomSmtpAddresses') {
                if ($null -eq $copy.PSObject.Properties[$property]) { continue }
                $value=[string]$copy.$property
                if ($value -match '^[\s]*[=+\-@]') { $copy.$property="'"+$value }
            }
            $rows.Add($copy)
        }
    }
    end {
        if ($rows.Count -eq 0) { throw 'No report rows were supplied; no CSV was created.' }
        $text=($rows | ConvertTo-Csv -NoTypeInformation)-join "`r`n"
        [IO.File]::WriteAllText($outputPath, $text+"`r`n", (New-Object Text.UTF8Encoding($true)))
        [PSCustomObject]@{Path=$outputPath; RowCount=$rows.Count }
    }
}
