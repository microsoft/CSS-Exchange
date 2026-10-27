# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#cspell:ignore Cascadia colgroup Consolas labelledby linecap linejoin middot minmax rgba Segoe tbody uarr

function Write-FreeBusyHtmlReport {
    $tableEnd = if ($Script:htmlTableOpen) { "</table>" } else { "" }
    @"
$Script:html
$tableEnd
<footer class='report-footer'>
  <div><strong>FreeBusyChecker</strong><span>Microsoft CSS &middot; Exchange diagnostics</span></div>
  <p>This report is a configuration snapshot. Review nonstandard values in the context of your environment before making changes.</p>
  <a href='#top'>Back to top &uarr;</a>
</footer>
</main>
</body>
</html>
"@ | Out-File -FilePath $Script:htmlFile -Encoding utf8
}

function showParametersHtml() {
    $Script:htmlTableOpen = $false
    $generatedAt = [System.Net.WebUtility]::HtmlEncode((Get-Date -Format "dd MMM yyyy, HH:mm zzz"))
    $serverName = [System.Net.WebUtility]::HtmlEncode([string]$Script:Server)
    $onPremDomain = [System.Net.WebUtility]::HtmlEncode([string]$Script:ExchangeOnPremDomain)
    $onlineDomain = [System.Net.WebUtility]::HtmlEncode([string]$Script:ExchangeOnlineDomain)
    $onPremMailbox = [System.Net.WebUtility]::HtmlEncode([string]$Script:UserOnPrem)
    $onlineMailbox = [System.Net.WebUtility]::HtmlEncode([string]$Script:UserOnline)
    $styles = @'
:root {
  color-scheme: light;
  --page: #f3f6fb;
  --surface: #ffffff;
  --ink: #172b45;
  --muted: #5d6d83;
  --line: #e2e8f0;
  --accent: #007f88;
  --good: #087443;
  --bad: #b42332;
  --warn: #925b0a;
  --shadow: 0 8px 28px rgba(23, 43, 69, 0.05);
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; scroll-padding-top: 100px; }
body { margin: 0; background: var(--page); color: var(--ink); font: 14px/1.65 "Segoe UI", -apple-system, BlinkMacSystemFont, Arial, sans-serif; }
a { color: #006f92; text-decoration: none; text-underline-offset: 3px; }
a:hover { text-decoration: underline; }
a:focus-visible, summary:focus-visible { outline: 3px solid #009ba5; outline-offset: 5px; border-radius: 4px; }
.hero { position: relative; overflow: hidden; color: #ffffff; background: radial-gradient(ellipse at 92% 10%, #176478 0, transparent 56%), linear-gradient(120deg, #10243d, #173b58); }
.hero::after { content: ""; position: absolute; width: 420px; height: 420px; right: -120px; top: -220px; border: 1px solid rgba(255,255,255,0.12); border-radius: 50%; box-shadow: 0 0 0 60px rgba(255,255,255,0.03), 0 0 0 120px rgba(255,255,255,0.02); pointer-events: none; }
.hero-inner, .report-main { max-width: 1200px; margin: 0 auto; padding: 0 28px; }
.hero-inner { position: relative; z-index: 1; padding-top: 28px; padding-bottom: 60px; }
.brand { display: flex; align-items: center; gap: 12px; color: #d3e1ef; font-size: 12px; letter-spacing: 0.04em; }
.brand strong { color: #ffffff; font-weight: 600; }
.brand-divider { width: 1px; height: 16px; background: #537087; }
.microsoft { display: grid; grid-template-columns: repeat(2, 10px); gap: 2px; }
.microsoft span { height: 10px; background: #f25022; }
.microsoft span:nth-child(2) { background: #7fba00; }
.microsoft span:nth-child(3) { background: #00a4ef; }
.microsoft span:nth-child(4) { background: #ffb900; }
.hero-content { display: flex; justify-content: space-between; align-items: flex-end; gap: 32px; margin-top: 36px; }
.eyebrow { margin: 0 0 10px; color: #8be1e1; font-size: 11px; font-weight: 700; letter-spacing: 0.16em; text-transform: uppercase; }
h1 { margin: 0; color: #ffffff; font-size: 44px; font-weight: 650; letter-spacing: -0.035em; line-height: 1.15; }
h1 span { display: block; margin-top: 10px; color: #d3e1ef; font-size: 23px; font-weight: 400; letter-spacing: -0.01em; }
.hero-description { max-width: 560px; margin: 18px 0 0; color: #c1d3e4; font-size: 14px; }
.report-meta { min-width: 235px; padding: 18px 22px; background: rgba(255,255,255,0.07); border: 1px solid rgba(255,255,255,0.14); border-radius: 14px; }
.report-meta span { display: block; color: #c1d3e4; font-size: 12px; }
.report-meta strong { display: block; margin: 4px 0 12px; color: #ffffff; font-size: 14px; font-weight: 600; }
.report-meta .read-only { display: inline-flex; gap: 7px; align-items: center; color: #a7eece; font-size: 11px; font-weight: 600; }
.read-only::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.report-nav { position: sticky; top: 12px; z-index: 10; display: flex; align-items: center; gap: 4px; width: calc(100% - 56px); max-width: 1144px; margin: -24px auto 28px; padding: 8px; background: var(--surface); border: 1px solid var(--line); border-radius: 14px; box-shadow: 0 6px 24px rgba(16,36,61,0.09); }
.report-nav a { padding: 10px 18px; border-radius: 8px; color: #475569; font-size: 13px; font-weight: 600; }
.report-nav a:hover { background: #edf7f8; color: var(--accent); text-decoration: none; }
.nav-note { margin-left: auto; padding-right: 14px; color: var(--muted); font-size: 11px; }
.overview-grid { display: grid; grid-template-columns: minmax(0,1fr) 40px minmax(0,1fr); align-items: center; gap: 18px; margin-bottom: 28px; }
.environment-card { min-width: 0; padding: 24px; background: var(--surface); border: 1px solid var(--line); border-radius: 16px; box-shadow: var(--shadow); }
.environment-label { display: flex; align-items: center; gap: 10px; color: var(--muted); font-size: 12px; font-weight: 600; }
.environment-icon { display: inline-flex; align-items: center; justify-content: center; width: 34px; height: 34px; border-radius: 10px; background: #edf3fd; color: #3367ad; }
.environment-icon svg { width: 20px; height: 20px; }
.cloud .environment-icon { color: #007f88; background: #e7f6f5; }
.environment-domain { margin: 14px 0 12px; font-size: 22px; font-weight: 650; letter-spacing: -0.025em; overflow-wrap: anywhere; }
.environment-mailbox { margin: 0; color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }
.environment-mailbox strong { margin-right: 6px; color: #475569; font-weight: 600; }
.connection { display: flex; align-items: center; justify-content: center; width: 40px; height: 40px; color: var(--accent); border: 1px solid #d5e8ea; border-radius: 50%; background: #e9f4f6; }
.connection svg { width: 22px; height: 22px; }
.section-heading { display: flex; align-items: flex-start; justify-content: space-between; flex-wrap: wrap; gap: 12px; margin: 30px 0 16px; }
h2 { margin: 0; color: var(--ink); font-size: 22px; font-weight: 650; letter-spacing: -0.025em; line-height: 1.4; }
.section-heading p { margin: 5px 0 0; color: var(--muted); font-size: 12px; }
.parameter-grid { display: grid; grid-template-columns: repeat(2,minmax(0,1fr)); gap: 1px; margin: 0; padding: 1px; overflow: hidden; background: var(--line); border: 1px solid var(--line); border-radius: 14px; box-shadow: var(--shadow); }
.parameter-grid > div { min-width: 0; padding: 17px 22px; background: var(--surface); }
.parameter-grid dt { margin-bottom: 5px; color: var(--muted); font-size: 10px; font-weight: 650; letter-spacing: 0.07em; text-transform: uppercase; }
.parameter-grid dd { margin: 0; color: #263d55; font: 12px/1.7 Consolas, "Cascadia Code", monospace; overflow-wrap: anywhere; }
.notice { display: flex; align-items: flex-start; gap: 14px; margin: 22px 0; padding: 18px 22px; border: 1px solid #d9e7f5; border-radius: 12px; background: #eaf3fc; }
.notice-icon { flex: 0 0 24px; width: 24px; height: 24px; border: 1px solid #a6c5e1; border-radius: 50%; color: #2b6392; font-weight: 700; text-align: center; line-height: 22px; }
.notice strong { color: #254e74; font-size: 13px; }
.notice p { margin: 3px 0 0; color: #43627e; font-size: 12px; }
.notice a { font-weight: 600; }
.resources-card { margin: 22px 0 30px; background: var(--surface); border: 1px solid var(--line); border-radius: 14px; box-shadow: var(--shadow); }
.resources-card summary { padding: 17px 22px; color: var(--ink); font-size: 13px; font-weight: 600; cursor: pointer; }
.resources-card summary::marker { color: var(--accent); }
.resource-count { margin-left: 10px; color: var(--muted); font-size: 11px; font-weight: 400; }
.resources-card ul { display: grid; grid-template-columns: repeat(2,minmax(0,1fr)); gap: 12px 24px; margin: 0; padding: 0 22px 22px; list-style: none; }
.resources-card li { padding-top: 12px; border-top: 1px solid var(--line); font-size: 12px; }
.status-key { display: flex; flex-wrap: wrap; gap: 14px; align-items: center; padding-top: 8px; color: var(--muted); font-size: 11px; }
.status-key span { display: inline-flex; align-items: center; gap: 6px; }
.status-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--good); }
.status-dot.review { background: var(--warn); }
.status-dot.attention { background: var(--bad); }
.method-heading { margin-top: 20px; padding: 20px 24px 12px; background: var(--surface); border: 1px solid var(--line); border-bottom: 0; border-radius: 14px 14px 0 0; }
.method-heading h3 { margin: 0 0 7px; font-size: 14px; font-weight: 600; }
.method-heading p { margin: 0; font-size: 12px; }
.method-heading p span { padding-left: 0 !important; color: #475569 !important; }
.method-help { margin-bottom: 26px; padding: 0 24px 20px; background: var(--surface); border: 1px solid var(--line); border-top: 0; border-radius: 0 0 14px 14px; }
.method-help ul { margin: 0; padding-left: 18px; color: var(--muted); font-size: 12px; }
.method-help li { margin-top: 10px; }
.method-help br { display: none; }
.method-help span { display: block; padding-left: 0 !important; font-family: Consolas, "Cascadia Code", monospace; font-size: 11px; }
.Black > p:empty { display: none; }
.Black h2 { margin: 32px 0 16px; font-size: 21px; }
.Black h2 b { font-weight: 650; }
table { width: 100%; margin: 16px 0 28px; overflow: hidden; border: 1px solid var(--line); border-spacing: 0; border-radius: 14px; background: var(--surface); box-shadow: var(--shadow); table-layout: fixed; }
.command-column { width: 32%; }
.result-column { width: 68%; }
th { padding: 13px 22px; background: #edf2f8; color: #3c516a !important; font-size: 12px; font-weight: 650; text-align: left; border-bottom: 1px solid var(--line); overflow-wrap: anywhere; }
th.table-section { padding: 18px 22px; background: #173b58; color: #ffffff !important; font-size: 14px; text-align: left !important; letter-spacing: 0.01em; }
td { padding: 20px 22px; vertical-align: top; border-bottom: 1px solid var(--line); font-size: 13px; overflow-wrap: anywhere; word-break: normal; }
td:first-child { width: 32%; background: #f8fafc; color: #53647b; font-family: Consolas, "Cascadia Code", monospace; font-size: 12px; line-height: 1.8; }
td:first-child b { font-weight: 500; }
td > div + div { margin-top: 8px; }
td > div > b { margin-right: 6px; color: #485b72; font-weight: 600; }
td > div > span { overflow-wrap: anywhere; }
tr:last-child td { border-bottom: 0; }
.green, [style*="color:green" i], [style*="color: green" i] { color: var(--good) !important; }
.red, [style*="color:red" i], [style*="color: red" i] { color: var(--bad) !important; }
.yellow, .orange, [style*="color:yellow" i], [style*="color: yellow" i], [style*="color:orange" i], [style*="color: orange" i] { color: var(--warn) !important; }
.black, [style*="color:black" i], [style*="color: black" i] { color: var(--ink) !important; }
.white { color: #ffffff; }
td span[style*="color:green" i]::before, td span[style*="color: green" i]::before,
td span[style*="color:red" i]::before, td span[style*="color: red" i]::before,
td span[style*="color:yellow" i]::before, td span[style*="color: yellow" i]::before {
  content: ""; display: inline-block; width: 6px; height: 6px; margin-right: 7px; border-radius: 50%; background: currentColor; vertical-align: middle;
}
.report-footer { display: flex; align-items: flex-start; gap: 28px; margin-top: 36px; padding: 24px 0 12px; border-top: 1px solid #d7e1ed; color: var(--muted); font-size: 11px; }
.report-footer > div { flex-shrink: 0; }
.report-footer strong { display: block; color: #42576e; font-size: 12px; }
.report-footer span { display: block; margin-top: 3px; }
.report-footer p { max-width: 570px; margin: 0; }
.report-footer a { margin-left: auto; flex-shrink: 0; font-weight: 600; }
@media (max-width: 760px) {
  .hero-inner, .report-main { padding-left: 18px; padding-right: 18px; }
  .hero-inner { padding-top: 24px; padding-bottom: 48px; }
  .hero-content { align-items: stretch; flex-direction: column; gap: 24px; margin-top: 28px; }
  h1 { font-size: 34px; }
  h1 span { font-size: 20px; }
  .hero-description { font-size: 13px; }
  .report-meta { min-width: 0; }
  .report-nav { position: relative; top: auto; display: grid; grid-template-columns: repeat(2,minmax(0,1fr)); width: auto; margin: -20px 18px 24px; }
  .report-nav a { padding: 9px 12px; text-align: center; }
  .nav-note { display: none; }
  .overview-grid { grid-template-columns: minmax(0,1fr); gap: 14px; }
  .connection { display: none; }
  .environment-card { padding: 20px; }
  .environment-domain { font-size: 20px; }
  .parameter-grid, .resources-card ul { grid-template-columns: minmax(0,1fr); }
  .parameter-grid > div { padding: 15px 18px; }
  .notice { padding: 16px 18px; }
  table, tbody, tr, th, td { display: block; width: 100% !important; }
  colgroup { display: none; }
  td { padding: 16px 18px; }
  th, th.table-section { padding-left: 18px; padding-right: 18px; }
  td:first-child { border-bottom: 1px dashed var(--line); }
  .method-heading { padding: 18px 18px 10px; }
  .method-help { padding: 0 18px 18px; }
  .report-footer { flex-direction: column; gap: 12px; }
  .report-footer a { margin-left: 0; }
}
@media (prefers-reduced-motion: reduce) {
  html { scroll-behavior: auto; }
}
@media print {
  body { background: #ffffff; color: #172b45; font-size: 10pt; }
  .hero { color: #172b45; background: #ffffff; border-bottom: 2px solid #173b58; }
  .hero::after, .report-nav, .connection, .report-footer a { display: none; }
  .hero-inner { padding-top: 0; padding-bottom: 20px; }
  .brand, .brand strong, h1, h1 span, .hero-description, .eyebrow, .report-meta span, .report-meta strong { color: #172b45; }
  .report-meta { border-color: #e2e8f0; }
  .report-meta .read-only { color: #087443; }
  .overview-grid { margin-top: 20px; }
  .environment-card, .parameter-grid, .resources-card, table { box-shadow: none; }
  .environment-card, .notice, .parameter-grid > div, tr { break-inside: avoid; }
  .resources-card summary { cursor: auto; }
  a { color: #172b45; text-decoration: underline; }
  th.table-section { background: #edf2f8; color: #172b45 !important; }
  .report-main { max-width: none; padding: 0; }
  .report-footer { margin-top: 20px; }
}
'@
    $Script:html = @"
<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>Hybrid Free Busy Configuration Checker</title>
<style>
$styles
</style>
</head>
<body>
<header class='hero' id='top'>
  <div class='hero-inner'>
    <div class='brand'>
      <span class='microsoft' aria-hidden='true'><span></span><span></span><span></span><span></span></span>
      <strong>Microsoft CSS</strong><span class='brand-divider' aria-hidden='true'></span><span>Exchange diagnostics</span>
    </div>
    <div class='hero-content'>
      <div>
        <p class='eyebrow'>Exchange hybrid diagnostics</p>
        <h1>Hybrid Free/Busy<span>Configuration report</span></h1>
        <p class='hero-description'>A clear view of your hybrid availability configuration, authentication settings, and connectivity checks.</p>
      </div>
      <div class='report-meta'>
        <span>Generated</span><strong>$generatedAt</strong>
        <span>Server: $serverName</span>
        <span class='read-only'>Read-only configuration assessment</span>
      </div>
    </div>
  </div>
</header>
<nav class='report-nav' aria-label='Report sections'>
  <a href='#overview'>Overview</a><a href='#environment'>Environment</a><a href='#diagnostics'>Diagnostics</a><a href='#resources'>Resources</a>
  <span class='nav-note'>FreeBusyChecker &middot; HTML report</span>
</nav>
<main class='report-main'>
  <section class='overview-grid' id='overview' aria-label='Hybrid environment overview'>
    <div class='environment-card'>
      <div class='environment-label'>
        <span class='environment-icon' aria-hidden='true'><svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.5'><rect x='4' y='3' width='16' height='7' rx='2'/><rect x='4' y='14' width='16' height='7' rx='2'/><path d='M8 6.5h.01M8 17.5h.01M12 6.5h5M12 17.5h5'/></svg></span>
        Exchange on-premises
      </div>
      <p class='environment-domain'>$onPremDomain</p>
      <p class='environment-mailbox'><strong>Mailbox</strong>$onPremMailbox</p>
    </div>
    <span class='connection' aria-hidden='true'><svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'><path d='M4 8h16m-4-4 4 4-4 4M20 16H4m4-4-4 4 4 4'/></svg></span>
    <div class='environment-card cloud'>
      <div class='environment-label'>
        <span class='environment-icon' aria-hidden='true'><svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.5'><path d='M7 18a4.5 4.5 0 0 1-.7-8.95 6 6 0 0 1 11.6-1.6A5.3 5.3 0 0 1 18 18H7Z'/></svg></span>
        Exchange Online
      </div>
      <p class='environment-domain'>$onlineDomain</p>
      <p class='environment-mailbox'><strong>Mailbox</strong>$onlineMailbox</p>
    </div>
  </section>
  <section id='environment' aria-labelledby='environment-title'>
    <div class='section-heading'><div><h2 id='environment-title'>Environment details</h2><p>The domains, mailboxes, and endpoints used for this assessment.</p></div></div>
    <dl class='parameter-grid'>
"@
    $parameters = @(
        @{ Name = "Server"; Value = $Script:Server }
        @{ Name = "AD root domain"; Value = $Script:ExchangeOnPremLocalDomain }
        @{ Name = "Exchange on-premises domain"; Value = $Script:ExchangeOnPremDomain }
        @{ Name = "Exchange Online domain"; Value = $Script:ExchangeOnlineDomain }
        @{ Name = "On-premises hybrid mailbox"; Value = $Script:UserOnPrem }
        @{ Name = "Exchange Online mailbox"; Value = $Script:UserOnline }
        @{ Name = "On-premises external EWS URL"; Value = $Script:ExchangeOnPremEWS }
        @{ Name = "Log file path"; Value = $Script:LogFile }
    )
    foreach ($parameter in $parameters) {
        $name = [System.Net.WebUtility]::HtmlEncode($parameter.Name)
        $value = [System.Net.WebUtility]::HtmlEncode([string]$parameter.Value)
        $Script:html += "<div><dt>$name</dt><dd>$value</dd></div>"
    }
    $Script:html += @"
    </dl>
  </section>
  <aside class='notice' aria-label='TLS prerequisite'>
    <span class='notice-icon' aria-hidden='true'>i</span>
    <div><strong>Start with a healthy TLS configuration</strong><p>TLS 1.2 should be enabled for hybrid Free/Busy. Confirm your TLS settings with the <a href='https://microsoft.github.io/CSS-Exchange/Diagnostics/HealthChecker/'>Microsoft Exchange Health Checker Script</a>.</p></div>
  </aside>
  <details class='resources-card' id='resources'>
    <summary>Reference library<span class='resource-count'>6 troubleshooting guides</span></summary>
    <ul>
      <li><a href='https://techcommunity.microsoft.com/t5/exchange-team-blog/demystifying-hybrid-free-busy-finding-errors-and-troubleshooting/ba-p/607727'>Demystifying Hybrid Free Busy: Finding Errors and Troubleshooting</a></li>
      <li><a href='https://support.microsoft.com/en-us/topic/how-to-troubleshoot-free-busy-issues-in-a-hybrid-deployment-of-on-premises-exchange-Server-and-exchange-online-in-office-365-ae03e199-b439-a84f-8db6-11bc0d7fbdf0'>How to Troubleshoot Free Busy Issues in a Hybrid Deployment of On-Premises Exchange Server and Exchange Online in Office 365</a></li>
      <li><a href='https://techcommunity.microsoft.com/t5/exchange-team-blog/the-hybrid-mesh/ba-p/605910'>The Hybrid Mesh</a></li>
      <li><a href='https://techcommunity.microsoft.com/t5/exchange-team-blog/how-to-address-federation-trust-issues-in-hybrid-configuration/ba-p/1144285'>How to Address Federation Trust Issues in Hybrid Configuration</a></li>
      <li><a href='https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?redirectSourcePath=%252farticle%252fOffice-365-URLs-and-IP-address-ranges-8548a211-3fe7-47cb-abb1-355ea5aa88a2&amp;view=o365-worldwide'>Office 365 URLs and IP Address Ranges</a></li>
      <li><a href='https://techcommunity.microsoft.com/legacyfs/online/media/2019/01/FB_Errors.FixesV6.pdf'>Free Busy Errors and Fixes</a></li>
    </ul>
  </details>
  <div class='section-heading' id='diagnostics'>
    <div><h2>Diagnostic details</h2><p>Collected settings and the original diagnostic findings. Nonstandard values may be intentional.</p></div>
    <div class='status-key' aria-label='Diagnostic color key'>
      <span><i class='status-dot' aria-hidden='true'></i>Expected value</span>
      <span><i class='status-dot review' aria-hidden='true'></i>Review</span>
      <span><i class='status-dot attention' aria-hidden='true'></i>Attention</span>
    </div>
  </div>
"@
    Write-FreeBusyHtmlReport
}
function orgRelHtml() {
    if ($Script:htmlTableOpen) {
        $Script:html += "</table>"
    }
    $Script:htmlTableOpen = $true
    $script:html += @"
 <div class='Black'><p></p></div>
 <div class='Black'><h2><b>`n Exchange On Premise Free Busy Configuration: `n</b></h2></div>
 <div class='Black'><p></p></div>
<table style='width:100%'>
<colgroup><col class='command-column'><col class='result-column'></colgroup>
<tr>
<th class='table-section' ColSpan='2' style='text-align:center; color:white;'><b>Exchange On Premise DAuth Configuration</b></th>
</tr>
<tr>
<th ColSpan='2' style='color:white;'>Summary - Get-OrganizationRelationship</th>
</tr>
<tr>
<td><b>Get-OrganizationRelationship</b></td>
<td>
"@
    foreach ($setting in $settingsList) {
        $color = $setting.Color
        if ($color -eq 'yellow') {
            $color = 'red'
        }
        $script:html += @"
    <div> <b>$($setting.Name): </b> <span style='color: $($color)'>$($setting.Value)</span></div>
"@
    }
    $script:html += @"
</td>
</tr>
"@
    Write-FreeBusyHtmlReport
}
function FedInfoHtml() {
    $script:html += "
<tr>
<th ColSpan='2' style='color:white;'>Summary - Get-FederationInformation</th>
</tr>
<tr>
<td><b>Get-FederationInformation -Domain $Script:ExchangeOnPremDomain</b></td>
<td>
  <div> <b>Domain Names: </b> <span style='color:$tdDomainNamesColor'>$tdDomainNamesFL</span></div>
  <div> <b>TokenIssuerUris: </b> <span style='color:$tdTokenIssuerUrisColor'>$tdTokenIssuerUrisFL</span></div>
  <div> <b>TarGetApplicationUri: </b> <span style='color:$tdTarGetApplicationUriColor'>$tdTarGetApplicationUriFL</span></div>
  <div> <b>TarGetAutoDiscoverEpr: </b> <span style='color:$tdTarGetAutoDiscoverEprColor'>$tdTarGetAutoDiscoverEprFL</span></div>
  <div> <b>TarGetApplicationUri - Federation Information vs Organization Relationship: </b> <span style='color:$tdTarGetAutoDiscoverEprVSColor'>$tdFederationInformationTA_FL</span></div>
  <div> <b>TarGetAutoDiscoverEpr - Federation Information vs Organization Relationship:</b> <span style='color:$tdTarGetAutoDiscoverEprVSColor'>$tdTarGetAutoDiscoverEprVS_FL</span></div>
</td>
</tr>
"
    Write-FreeBusyHtmlReport
}
function fedTrustHtml() {
    $script:html += "
<tr>
<th ColSpan='2' style='color:white;'>Summary - Test-FederationTrust</th>
</tr>
<tr>
<td><b>Get-FederationTrust | select ApplicationUri, TokenIssuerUri, OrgCertificate, TokenIssuerCertificate, TokenIssuerPrevCertificate, TokenIssuerMetadataEpr, TokenIssuerEpr</b></td>
<td>
<div> <b>Application Uri: </b> <span style='color:$tdFedTrustApplicationUriColor'>$tdFedTrustApplicationUriFL</span></div>
<div> <b>TokenIssuerUris: </b> <span style='color:$tdFedTrustTokenIssuerUriColor'>$tdFedTrustTokenIssuerUriFL</span></div>
<div> <b>Certificate Expiry: </b> <span style='color:$tdFedTrustOrgCertificateNotAfterDateColor'>$tdFedTrustOrgCertificateNotAfterDateFL</span></div>
<div> <b>Token Issuer Certificate Expiry: </b> <span style='color:$tdFedTrustTokenIssuerCertificateNotAfterDateTimeColor'>$tdFedTrustTokenIssuerCertificateNotAfterDateTimeFL</span></div>
<div> <b>Token Issuer Metadata EPR:</b> <span style='color:$tdFedTrustTokenIssuerMetadataEprAbsoluteUriColor'>$tdFedTrustTokenIssuerMetadataEprAbsoluteUriFL</span></div>
<div> <b>Token Issuer EPR: </b> <span style='color:$tdFedTrustTokenIssuerEprAbsoluteUriColor'>$tdFedTrustTokenIssuerEprAbsoluteUriFL</span></div>

</td>
</tr>
"
    Write-FreeBusyHtmlReport
}
function AvailabilityAddressSpaceHtml() {
    $script:html += "
<tr>
<th ColSpan='2' style='color:white;'>Summary - On-Premise Get-AvailabilityAddressSpace</th>
</tr>
<tr>
<td><b> Get-AvailabilityAddressSpace $Script:ExchangeOnlineDomain | fl ForestName, UserName, UseServiceAccount, AccessMethod, ProxyUrl, Name</b></td>
<td>
<div> <b>Forest Name: </b> $Script:tdAvailabilityAddressSpaceForestName</div>
<div> <b>Name: </b>$Script:tdAvailabilityAddressSpaceName</div>
<div> <b>UserName: </b> <span style='color:$Script:tdAvailabilityAddressSpaceUserNameColor'>$Script:tdAvailabilityAddressSpaceUserName</span></div>
<div> <b>Access Method: </b> <span style='color:$Script:tdAvailabilityAddressSpaceAccessMethodColor'>$Script:tdAvailabilityAddressSpaceAccessMethod</span></div>
<div> <b>ProxyUrl: </b> <span style='color:$Script:tdAvailabilityAddressSpaceProxyUrlColor'>$Script:tdAvailabilityAddressSpaceProxyUrl</span></div>
</td>
</tr>"
    Write-FreeBusyHtmlReport
}
function autoDVDHtmlOK() {
    $script:html +=
    "<tr>
<th ColSpan='2' style='color:white;'>Summary - Get-AutoDiscoverVirtualDirectory</th>
</tr>
<tr>
<td><b>Get-AutoDiscoverVirtualDirectory | Select Identity,Name,ExchangeVersion,*authentication*</b></td>
<td>
<div><b>============================</b></div>
<div><b>Identity:</b> $Script:AutoD_VD_Identity</div>
<div><b>Name:</b> $Script:AutoD_VD_Name </div>
<div><b>InternalAuthenticationMethods:</b> $Script:AutoD_VD_InternalAuthenticationMethods </div>
<div><b>ExternalAuthenticationMethods:</b> $Script:AutoD_VD_ExternalAuthenticationMethods </div>
<div><b>WSAuthentication:</b> <span style='color:green'>$Script:AutoD_VD_WSAuthentication</span></div>
<div><b>WindowsAuthentication:</b> <span style='color:green'>$Script:AutoD_VD_WindowsAuthentication</span></div>
"
    Write-FreeBusyHtmlReport
}
function autoDVDHtmlNotOK() {
    $script:html +=
    "<tr>
<th ColSpan='2' style='color:white;'>Summary - Get-AutoDiscoverVirtualDirectory</th>
</tr>
<tr>
<td><b>Get-AutoDiscoverVirtualDirectory | Select Identity,Name,ExchangeVersion,*authentication*</b></td>
<td>
<div><b>============================</b></div>
<div><b>Identity:</b> $Script:AutoD_VD_Identity</div>
<div><b>Name:</b> $Script:AutoD_VD_Name </div>
<div><b>InternalAuthenticationMethods:</b> $Script:AutoD_VD_InternalAuthenticationMethods </div>
<div><b>ExternalAuthenticationMethods:</b> $Script:AutoD_VD_ExternalAuthenticationMethods </div>
<div><b>WSAuthentication:</b> <span style='color:green'>$Script:AutoD_VD_WSAuthentication</span></div>
<div><b>WindowsAuthentication:</b> <span style='color:green'>$Script:AutoD_VD_WindowsAuthentication</span></div>
"
    Write-FreeBusyHtmlReport
}
function EWSVirtualDHeaderHtml() {
    $script:html += "
<tr>
<th ColSpan='2' style='color:white;'>Summary - Get-WebServicesVirtualDirectory</th>
</tr>
<tr>
<td><b> Get-WebServicesVirtualDirectory | Select Identity,Name,ExchangeVersion,*Authentication*,*url</b></td>
<td >"
    Write-FreeBusyHtmlReport
}
function EwsVDHtmlOK() {
    $script:html +=
    " <div><b>============================</b></div>
<div><b>Identity:</b>$Script:EwsVDIdentity</div>
<div><b>Name:</b>$Script:EwsVDName </div>
<div><b>InternalAuthenticationMethods:</b>$Script:EwsVDInternalAuthenticationMethods </div>
<div><b>ExternalAuthenticationMethods:</b>$Script:EwsVDExternalAuthenticationMethods </div>
<div><b>WSAuthentication:</b> <span style='color:green'>$EwsVD_WSAuthentication</span></div>
<div><b>WindowsAuthentication:</b> <span style='color:$Script:EwsVDWindowsAuthenticationColor'>$Script:EwsVDWindowsAuthentication</span></div>
<div><b>InternalUrl:</b>$Script:EwsVDInternalUrl </div>
<div><b>ExternalUrl:</b>$Script:EwsVDExternalUrl </div>"
    Write-FreeBusyHtmlReport
}
function EwsVDHtmlNotOK() {
    $script:html +=
    " <div><b>============================</b></div>
<div><b>Identity:</b>$Script:EwsVDIdentity</div>
<div><b>Name:</b>$Script:EwsVDName </div>
<div><b>InternalAuthenticationMethods:</b>$Script:EwsVDInternalAuthenticationMethods </div>
<div><b>ExternalAuthenticationMethods:</b>$Script:EwsVDExternalAuthenticationMethods </div>
<div><b>WSAuthentication:</b> <span style='color:red'>$EwsVD_WSAuthentication</span></div>
<div><b>WindowsAuthentication:</b> <span style='color:$Script:EwsVDWindowsAuthenticationColor'>$Script:EwsVDWindowsAuthentication</span></div>
<div><b>InternalUrl:</b>$Script:EwsVDInternalUrl </div>
<div><b>ExternalUrl:</b>$Script:EwsVDExternalUrl </div>"
    Write-FreeBusyHtmlReport
}
function TestOrgRelHtmlOK() {
    $Script:html += "<tr>
<th ColSpan='2' style='color:white;'><b>Summary - Test-OrganizationRelationship</b></th>
</tr>
<tr>
<td><b>Test-OrganizationRelationship -Identity $Script:OrgRelIdentity  -UserIdentity $Script:UserOnPrem</b></td>
<td>
<div class='green'> <b>No Significant Issues to Report</b></div>
</td>
</tr>"
    Write-FreeBusyHtmlReport
}
function TestOrgRelHtmlNotOK() {
    $Script:html += "<tr>
<th ColSpan='2' style='color:white;'><b>Summary - Test-OrganizationRelationship</b></th>
</tr>
<tr>
<td><b>Test-OrganizationRelationship -Identity $Script:OrgRelIdentity  -UserIdentity $Script:UserOnPrem</b></td>
<td>
<div class='red'> <b>Test Organization Relationship Completed with errors</b></div>
</td>
</tr>"
    Write-FreeBusyHtmlReport
}
function TestOrgRelHtmlNoUri() {
    $Script:html += "
<tr>
<th ColSpan='2' style='color:white;'><b>Summary - Test-OrganizationRelationship</b></th>
</tr>
<tr>
<td><b>Test-OrganizationRelationship</b></td>
<td>
<div class='red'> <b> Test-OrganizationRelationship can't be run if the Organization Relationship Target Application uri is not correct. Organization Relationship Target Application Uri should be Outlook.com</b></div>
</td>
</tr>"
    Write-FreeBusyHtmlReport
}
#On Prem OAuth
function IntraOrgConCheckHtml() {
    if ($Script:htmlTableOpen) {
        $Script:html += "</table>"
    }
    $Script:htmlTableOpen = $true
    # Build HTML table row
    if ($Auth -like "OAuth") {
        $Script:html += "
  <div class='Black'><p></p></div>
  <div class='Black'><h2><b>`n Exchange On Premise Free Busy Configuration: `n</b></h2></div>
  <div class='Black'><p></p></div>"
    }
    $Script:html += "
<table style='width:100%'>
<colgroup><col class='command-column'><col class='result-column'></colgroup>
<tr>
<th class='table-section' ColSpan='2' style='text-align:center; color:white;'>Exchange On Premise OAuth Configuration</th>
</tr>
<tr>
<th ColSpan='2' style='color:white;'>Summary - Get-IntraOrganizationConnector</th>
</tr>
<tr>
<td><b>Get-IntraOrganizationConnector:</b></td>
<td>
  <div><b>TarGet Address Domains:</b><span style='color: $Script:tdIntraOrgTarGetAddressDomainColor'>$($Script:tdIntraOrgTarGetAddressDomain)</span></div>
  <div><b>Discovery Endpoint:</b><span style='color: $Script:tdDiscoveryEndpointColor;'>$($Script:tdDiscoveryEndpoint)</span></div>
  <div><b>Enabled:</b><span style='color: $Script:tdEnabledColor;'>$($Script:tdEnabled)</span></div>
</td>
</tr>
"
    Write-FreeBusyHtmlReport
}
function AuthServerCheckHtml() {
    $Script:html += "
<tr>
  <th ColSpan='2' style='color:white;'>Summary - Get-AuthServer</th>
</tr>
<tr>
  <td><b> Get-AuthServer | Select Name,IssuerIdentifier,TokenIssuingEndpoint,AuthMetadataUrl,Enabled</b></td>
  <td>
    <div><b>IssuerIdentifier:</b><span style='color: $Script:tDAuthServerIssuerIdentifierColor'>$($Script:tDAuthServerIssuerIdentifier)</span></div>
    <div><b>TokenIssuingEndpoint:</b><span style='color: $Script:tDAuthServerTokenIssuingEndpointColor;'>$($Script:tDAuthServerTokenIssuingEndpoint)</span></div>
    <div><b>AuthMetadataUrl:</b><span style='color: $Script:tDAuthServerAuthMetadataUrlColor;'>$($Script:tDAuthServerAuthMetadataUrl)</span></div>
    <div><b>Enabled:</b><span style='color: $Script:tDAuthServerEnabledColor;'>$($Script:tDAuthServerEnabled)</span></div>
  </td>
</tr>
"
    Write-FreeBusyHtmlReport
}
function PartnerApplicationCheckHtml() {
    $Script:html += "
<tr>
  <th ColSpan='2' style='color:white;'>Summary - Get-PartnerApplication</th>
</tr>
<tr>
  <td><b> Get-PartnerApplication |  ?{`$_.ApplicationIdentifier -eq '00000002-0000-0ff1-ce00-000000000000'
-and `$_.Realm -eq ''} | Select Enabled, ApplicationIdentifier, CertificateStrings, AuthMetadataUrl, Realm, UseAuthServer,
AcceptSecurityIdentifierInformation, LinkedAccount, IssuerIdentifier, AppOnlyPermissions, ActAsPermissions, Name</b></td>
  <td>
    <div><b>Enabled:</b><span style='color:$Script:tdPartnerApplicationEnabledColor'>$($tdPartnerApplicationEnabled)</span></div>
    <div><b>ApplicationIdentifier:</b><span style='color:$Script:tdPartnerApplicationApplicationIdentifierColor;'>$($tdPartnerApplicationApplicationIdentifier)</span></div>
    <div><b>CertificateStrings:</b><span style='color:$Script:tdPartnerApplicationCertificateStringsColor;'>$($tdPartnerApplicationCertificateStrings)</span></div>
    <div><b>AuthMetadataUrl:</b><span style='color:$Script:tdPartnerApplicationAuthMetadataUrlColor;'>$($tdPartnerApplicationAuthMetadataUrl)</span></div>
    <div><b>Realm:</b><span style='color:$Script:tdPartnerApplicationRealmColor'>$($tdPartnerApplicationRealm)</span></div>
    <div><b>LinkedAccount:</b><span style='color:$Script:tdPartnerApplicationLinkedAccountColor;'>$($tdPartnerApplicationLinkedAccount)</span></div>
    <div><b>IssuerIdentifier:</b><span style='color:$Script:tdPartnerApplicationEnabledColor'>$($tdPartnerApplicationEnabled)</span></div>
    <div><b>AppOnlyPermissions:</b><span style='color:$Script:tdPartnerApplicationApplicationIdentifierColor;'>$($tdPartnerApplicationApplicationIdentifier)</span></div>
    <div><b>ActAsPermissions:</b><span style='color:$Script:tdPartnerApplicationCertificateStringsColor;'>$($tdPartnerApplicationCertificateStrings)</span></div>
    <div><b>Name:</b><span style='color:$Script:tdPartnerApplicationAuthMetadataUrlColor;'>$($tdPartnerApplicationAuthMetadataUrl)</span></div>
  </td>
</tr>
"
    Write-FreeBusyHtmlReport
}
function ApplicationAccountCheckHtml() {
    $Script:html += "
  <tr>
  <th ColSpan='2' style='color:white;'>Summary - Get-User ApplicationAccount</th>
</tr>
<tr>
  <td><b>  Get-user '$Script:ExchangeOnPremLocalDomain/Users/Exchange Online-ApplicationAccount' | Select Name, RecipientType, RecipientTypeDetails, UserAccountControl':</b></td>
  <td>
    <div><b>RecipientType:</b><span style='color: $Script:tdApplicationAccountRecipientTypeColor'>$($Script:tdApplicationAccountRecipientType)</span></div>
    <div><b>RecipientTypeDetails:</b><span style='color: $Script:tdApplicationAccountRecipientTypeDetailsColor;'>$($Script:tdApplicationAccountRecipientTypeDetails)</span></div>
    <div><b>UserAccountControl:</b><span style='color: $Script:tdApplicationAccountUserAccountControlColor;'>$($Script:tdApplicationAccountUserAccountControl)</span></div>

  </td>
</tr>
"
    Write-FreeBusyHtmlReport
}
function ManagementRoleAssignmentCheckHtml() {
    $Script:html += "
<tr>
<th ColSpan='2' style='color:white;'>Summary - Get-ManagementRoleAssignment</th>
</tr>
<tr>
<td><b>  Get-ManagementRoleAssignment -RoleAssignee Exchange Online-ApplicationAccount | Select Name,Role</b></td>
<td>
  <div><b>UserApplication Role:</b><span style='color: $Script:tdManagementRoleAssignmentUserApplicationColor'>$($Script:tdManagementRoleAssignmentUserApplication)</span></div>
  <div><b>ArchiveApplication Role:</b><span style='color: $Script:tdManagementRoleAssignmentArchiveApplicationColor;'>$($Script:tdManagementRoleAssignmentArchiveApplication)</span></div>
  <div><b>LegalHoldApplication Role:</b><span style='color: $Script:tdManagementRoleAssignmentLegalHoldApplicationColor;'>$($Script:tdManagementRoleAssignmentLegalHoldApplication)</span></div>
  <div><b>Mailbox Search Role:</b><span style='color: $Script:tdManagementRoleAssignmentMailboxSearchColor'>$($Script:tdManagementRoleAssignmentMailboxSearch)</span></div>
  <div><b>TeamMailboxLifecycleApplication Role:</b><span style='color: $Script:tdManagementRoleAssignmentTeamMailboxLifecycleApplicationColor;'>$($Script:tdManagementRoleAssignmentTeamMailboxLifecycleApplication)</span></div>
  <div><b>MailboxSearchApplication Role:</b><span style='color: $Script:tdManagementRoleMailboxSearchApplicationColor;'>$($Script:tdManagementRoleMailboxSearchApplication)</span></div>
  <div><b>MeetingGraphApplication Role:</b><span style='color: $Script:tdManagementRoleMeetingGraphApplicationColor;'>$($Script:tdManagementRoleMeetingGraphApplication)</span></div>
</td>
</tr>
"
    Write-FreeBusyHtmlReport
}
function AuthConfigCheckHtml() {
    $Script:html += "
  <tr>
  <th ColSpan='2' style='color:white;'>Summary - Get-AuthConfig</th>
</tr>
<tr>
  <td><b>  Get-AuthConfig | Select-Object *Thumbprint, ServiceName, Realm, Name</b></td>
  <td>
    <div><b>Name:</b><span >$($Script:tDAuthConfigName)</span></div>
    <div><b>Thumbprint:</b><span style='color: $Script:tDAuthConfigCurrentCertificateThumbprintColor'>$($Script:tDAuthConfigCurrentCertificateThumbprint)</span></div>
    <div><b>ServiceName:</b><span style='color:$Script:tDAuthConfigServiceNameColor;'>$( $Script:tDAuthConfigServiceName)</span></div>
    <div><b>Realm:</b><span style='color: $Script:tDAuthConfigRealmColor;'>$($Script:tDAuthConfigRealm)</span></div>
  </td>
</tr>
"
    Write-FreeBusyHtmlReport
}
function CurrentCertificateThumbprintCheckHtml() {
    $Script:html += "
<tr>
<th ColSpan='2' style='color:white;'>Summary - Get-ExchangeCertificate AuthCertificate</th>
</tr>
<tr>
<td><b>  Get-ExchangeCertificate $thumb.CurrentCertificateThumbprint | Select-Object *</b></td>
<td>
  <div><b>Issuer:</b><span style='color:$Script:tdCurrentCertificateIssuerColor'>$($tdCurrentCertificateIssuer)</span></div>
  <div><b>Services:</b><span style='color:$Script:tdCurrentCertificateServicesColor'>$($tdCurrentCertificateServices)</span></div>
  <div><b>Status:</b><span style='color:$tdCurrentCertificateStatusColor;'>$($Script:tdCurrentCertificateStatus)</span></div>
  <div><b>Subject:</b><span style='color:$Script:tdCurrentCertificateSubjectColor;'>$($tdCurrentCertificateSubject)</span></div>
  <div><b>Distribution:</b><span style='color:$Script:tdCheckAuthCertDistributionColor;'>$($tdCheckAuthCertDistribution)</span></div>
</td>
</tr>
"
    Write-FreeBusyHtmlReport
}
function OAuthConnectivityCheckHtml() {
    $Script:html += "
  <tr>
  <th ColSpan='2' style='color:white;'>Summary - Test-OAuthConnectivity</th>
</tr>
<tr>
  <td><b>  Test-OAuthConnectivity -Service EWS -TarGetUri https://outlook.office365.com/EWS/Exchange.asmx -Mailbox $Script:UserOnPrem | fl</b></td>
  <td>
    <div><b>Result:</b><span style='color: $Script:OAuthConnectivityResultTypeColor'> $Script:OAuthConnectivityResultType</span></div>
  </td>
</tr>
"
    Write-FreeBusyHtmlReport
}
function AvailabilityAddressSpaceCheckOAuth() {
    Write-Host -ForegroundColor Green " Get-AvailabilityAddressSpace $Script:ExchangeOnlineDomain | Select ForestName, UserName, UseServiceAccount, AccessMethod, ProxyUrl, Name"
    PrintDynamicWidthLine
    $AvailabilityAddressSpace = Get-AvailabilityAddressSpace $Script:ExchangeOnlineDomain | Select-Object ForestName, UserName, UseServiceAccount, AccessMethod, ProxyUrl, Name
    $AAS = $AvailabilityAddressSpace | Format-List
    $AAS
    if ($Auth -contains "OAuth") {
    }
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - On-Prem Availability Address Space"
    PrintDynamicWidthLine
    Write-Host -ForegroundColor White " ForestName: "
    if ($AvailabilityAddressSpace.ForestName -like $Script:ExchangeOnlineDomain) {
        Write-Host -ForegroundColor Green " "$AvailabilityAddressSpace.ForestName
        $Script:tdAvailabilityAddressSpaceForestName = $AvailabilityAddressSpace.ForestName
        $Script:tdAvailabilityAddressSpaceForestNameColor = "green"
    } else {
        Write-Host -ForegroundColor Red " ForestName is NOT correct. "
        Write-Host -ForegroundColor White " Should be $Script:ExchangeOnlineDomain "
        $Script:tdAvailabilityAddressSpaceForestName = $AvailabilityAddressSpace.ForestName
        $Script:tdAvailabilityAddressSpaceForestNameColor = "red"
    }
    Write-Host -ForegroundColor White " UserName: "
    if ($AvailabilityAddressSpace.UserName -like "") {
        Write-Host -ForegroundColor Green "  Blank "
        $Script:tdAvailabilityAddressSpaceUserName = "  Blank. This is the correct value. "
        $Script:tdAvailabilityAddressSpaceUserNameColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  UserName is NOT correct. "
        Write-Host -ForegroundColor White "  Should be blank "
        $Script:tdAvailabilityAddressSpaceUserName = "  Blank. This is the correct value. "
        $Script:tdAvailabilityAddressSpaceUserNameColor = "red"
    }
    Write-Host -ForegroundColor White " UseServiceAccount: "
    if ($AvailabilityAddressSpace.UseServiceAccount -like "True") {
        Write-Host -ForegroundColor Green "  True "
        $Script:tdAvailabilityAddressSpaceUseServiceAccount = $AvailabilityAddressSpace.UseServiceAccount
        $Script:tdAvailabilityAddressSpaceUseServiceAccountColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  UseServiceAccount is NOT correct."
        Write-Host -ForegroundColor White "  Should be True "
        $Script:tdAvailabilityAddressSpaceUseServiceAccount = "$($tAvailabilityAddressSpace.UseServiceAccount). Should be True"
        $Script:tdAvailabilityAddressSpaceUseServiceAccountColor = "red"
    }
    Write-Host -ForegroundColor White " AccessMethod: "
    if ($AvailabilityAddressSpace.AccessMethod -like "InternalProxy") {
        Write-Host -ForegroundColor Green "  InternalProxy "
        $Script:tdAvailabilityAddressSpaceAccessMethod = $AvailabilityAddressSpace.AccessMethod
        $Script:tdAvailabilityAddressSpaceAccessMethodColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  AccessMethod is NOT correct. "
        Write-Host -ForegroundColor White "  Should be InternalProxy "
        $Script:tdAvailabilityAddressSpaceAccessMethod = $AvailabilityAddressSpace.AccessMethod
        $Script:tdAvailabilityAddressSpaceAccessMethodColor = "red"
    }
    Write-Host -ForegroundColor White " ProxyUrl: "
    if ($AvailabilityAddressSpace.ProxyUrl -like $Script:ExchangeOnPremEWS) {
        Write-Host -ForegroundColor Green " "$AvailabilityAddressSpace.ProxyUrl
        $Script:tdAvailabilityAddressSpaceProxyUrl = $AvailabilityAddressSpace.ProxyUrl
        $Script:tdAvailabilityAddressSpaceProxyUrlColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  ProxyUrl is NOT correct. "
        Write-Host -ForegroundColor White "  Should be $Script:ExchangeOnPremEWS"
        $Script:tdAvailabilityAddressSpaceProxyUrl = $AvailabilityAddressSpace.ProxyUrl
        $Script:tdAvailabilityAddressSpaceProxyUrlColor = "red"
    }
    AvailabilityAddressSpaceCheckOAuthHtml
}
function  AvailabilityAddressSpaceCheckOAuthHtml() {
    $Script:html += "
<tr>
<th ColSpan='2' style='color:white;'>Summary - Get-AvailabilityAddressSpace</th>
</tr>
<tr>
<td><b>  Get-AvailabilityAddressSpace $Script:ExchangeOnlineDomain | Select ForestName, UserName, UseServiceAccount, AccessMethod, ProxyUrl, Name</b></td>
<td>
  <div><b>AddressSpaceForestName:</b><span style='color: $Script:tdAvailabilityAddressSpaceForestNameColor'>$($Script:tdAvailabilityAddressSpaceForestName)</span></div>
  <div><b>AddressSpaceUserName:</b><span style='color: $Script:tdAvailabilityAddressSpaceUserNameColor'>$($Script:tdAvailabilityAddressSpaceUserName)</span></div>
  <div><b>UseServiceAccount:</b><span style='color:$Script:tdAvailabilityAddressSpaceUseServiceAccountColor;'>$( $Script:tdAvailabilityAddressSpaceUseServiceAccount)</span></div>
  <div><b>AccessMethod:</b><span style='color: $Script:tdAvailabilityAddressSpaceAccessMethodColor;'>$($Script:tdAvailabilityAddressSpaceAccessMethod)</span></div>
  <div><b>ProxyUrl:</b><span style='color: $Script:tdAvailabilityAddressSpaceProxyUrlColor;'>$($Script:tdAvailabilityAddressSpaceProxyUrl)</span></div>
</td>
</tr>
"
    Write-FreeBusyHtmlReport
}
function AutoDVirtualDCheckOauthHtmlHead() {
    $script:html += "<tr>
<th ColSpan='2' style='color:white;'>Summary - Get-AutoDiscoverVirtualDirectory</th>
</tr>
<tr>
<td><b>Get-AutoDiscoverVirtualDirectory:</b></td>
<td>"
    Write-FreeBusyHtmlReport
}
function  AutoDVirtualDCheckOauthHtmlOk() {
    $script:html +=
    " <div><b>============================</b></div>
        <div><b>Identity:</b> $Script:AutoD_VD_Identity</div>
        <div><b>Name:</b> $Script:AutoD_VD_Name </div>
        <div><b>InternalAuthenticationMethods:</b> $Script:AutoD_VD_InternalAuthenticationMethods </div>
        <div><b>ExternalAuthenticationMethods:</b> $Script:AutoD_VD_ExternalAuthenticationMethods </div>
        <div><b>WSAuthentication:</b> <span style='color:green'>$Script:AutoD_VD_WSAuthentication</span></div>
        <div><b>WindowsAuthentication:</b> <span style='color:green'>$Script:AutoD_VD_WindowsAuthentication</span></div>
        <div><b>OAuthAuthentication:</b> <span style='color:$Script:AutoD_VD_OAuthAuthenticationColor'>$Script:AutoD_VD_OAuthAuthentication</span></div>
        "
    Write-FreeBusyHtmlReport
}
function  AutoDVirtualDCheckOauthHtmlNotOk() {
    $script:html +=
    " <div><b>============================</b></div>
        <div><b>Identity:</b> $Script:AutoD_VD_Identity</div>
        <div><b>Name:</b> $Script:AutoD_VD_Name </div>
        <div><b>InternalAuthenticationMethods:</b> $Script:AutoD_VD_InternalAuthenticationMethods </div>
        <div><b>ExternalAuthenticationMethods:</b> $Script:AutoD_VD_ExternalAuthenticationMethods </div>
        <div><b>WSAuthentication:</b> <span style='color:red'>$Script:AutoD_VD_WSAuthentication</span></div>
        <div><b>WindowsAuthentication:</b> <span style='color:$Script:AutoD_VD_WindowsAuthenticationColor'>$Script:AutoD_VD_WindowsAuthentication</span></div>
        <div><b>OAuthAuthentication:</b> <span style='color:$Script:AutoD_VD_OAuthAuthenticationColor'>$Script:AutoD_VD_OAuthAuthentication</span></div>
        "
    Write-FreeBusyHtmlReport
}
function EWSVirtualDirectoryCheckOAuthHtmlHead() {
    $script:html += "
<tr>
<th ColSpan='2' style='color:white;'>Summary - Get-WebServicesVirtualDirectory</th>
</tr>
<tr>
<td><b>Get-WebServicesVirtualDirectory | Select Identity,Name,ExchangeVersion,*Authentication*,*url</b></td>
<td >"
    Write-FreeBusyHtmlReport
}
function  EWSVirtualDirectoryCheckOAuthHtmlOk() {
    $script:html +=
    " <div><b>============================</b></div>
        <div><b>Identity:</b>$Script:EwsVDIdentity</div>
        <div><b>Name:</b>$Script:EwsVDName </div>
        <div><b>InternalAuthenticationMethods:</b>$Script:EwsVDInternalAuthenticationMethods </div>
        <div><b>ExternalAuthenticationMethods:</b>$Script:EwsVDExternalAuthenticationMethods </div>
        <div><b>WSAuthentication:</b> <span style='color:green'>$EwsVD_WSAuthentication</span></div>
        <div><b>WindowsAuthentication:</b> <span style='color:$Script:EwsVDWindowsAuthenticationColor'>$Script:EwsVDWindowsAuthentication</span></div>
        <div><b>OAuthAuthentication:</b> <span style='color:$EwsVDW_OAuthAuthenticationColor'>$EwsVDOAuthAuthentication</span></div>
        <div><b>InternalUrl:</b>$Script:EwsVDInternalUrl </div>
        <div><b>ExternalUrl:</b>$Script:EwsVDExternalUrl </div>  "
    Write-FreeBusyHtmlReport
}
function  EWSVirtualDirectoryCheckOAuthHtmlNotOk() {
    $script:html +=
    " <div><b>============================</b></div>
        <div><b>Identity:</b>$Script:EwsVDIdentity</div>
        <div><b>Name:</b>$Script:EwsVDName </div>
        <div><b>InternalAuthenticationMethods:</b>$Script:EwsVDInternalAuthenticationMethods </div>
        <div><b>ExternalAuthenticationMethods:</b>$Script:EwsVDExternalAuthenticationMethods </div>
        <div><b>WSAuthentication:</b> <span style='color:red'>$EwsVD_WSAuthentication</span></div>
        <div><b>WindowsAuthentication:</b> <span style='color:$Script:EwsVDWindowsAuthenticationColor'>$Script:EwsVDWindowsAuthentication</span></div>
        <div><b>OAuthAuthentication:</b> <span style='color:$EwsVDW_OAuthAuthenticationColor'>$EwsVDOAuthAuthentication</span></div>
        <div><b>InternalUrl:</b>$Script:EwsVDInternalUrl </div>
        <div><b>ExternalUrl:</b>$Script:EwsVDExternalUrl </div>  "
    Write-FreeBusyHtmlReport
}
#Exo HTML DAuth output
function ExoOrgRelCheckHtml() {
    $script:html += "
<tr>
  <th class='table-section' ColSpan='2' style='text-align:center; color:white;'>Exchange Online DAuth Configuration</th>
</tr>
<tr>
<th ColSpan='2' style='color:white;'>Summary - Get-OrganizationRelationship</th>
</tr>
<tr>
<td><b>  Get-OrganizationRelationship  | Where{($_.DomainNames -like $Script:ExchangeOnPremDomain )} | Select Identity,DomainNames,FreeBusy*,TarGet*,Enabled</b></td>
<td>
  <div><b>Domain Names:</b><span >$($Script:tdExoOrgRelDomainNamesData)</span></div>
  <div><b>FreeBusyAccessEnabled:</b><span style='color:$Script:tdExoOrgRelFreeBusyAccessEnabledColor'>$($Script:tdExoOrgRelFreeBusyAccessEnabled)</span></div>
  <div><b>FreeBusyAccessLevel::</b><span style='color:$Script:tdExoOrgRelFreeBusyAccessLevelColor;'>$( $Script:tdExoOrgRelFreeBusyAccessLevel)</span></div>
  <div><b>TarGetApplicationUri:</b><span style='color: $Script:tdExoOrgRelTarGetApplicationUriColor;'>$($Script:tdExoOrgRelTarGetApplicationUri)</span></div>
  <div><b>TarGetOwAUrl:</b><span >$($tdExoOrgRelTarGetOwAUrl)</span></div>
  <div><b>TarGetSharingEpr:</b><span style='color: $Script:tdExoOrgRelTarGetSharingEprColor'>$($Script:tdExoOrgRelTarGetSharingEpr)</span></div>
  <div><b>TarGetAutoDiscoverEpr:</b><span style='color:$tdExoOrgRelFreeBusyAccessScopeColor;'>$($Script:tdExoOrgRelFreeBusyAccessScope)</span></div>
  <div><b>Enabled:</b><span style='color: $Script:tdExoOrgRelEnabledColor;'>$($Script:tdExoOrgRelEnabled)</span></div>
</td>
</tr>
"
    Write-FreeBusyHtmlReport
}
function ExoFedOrgIdCheckHtml() {
    $script:html += "
<tr>
<th ColSpan='2' style='color:white;'>Summary - Get-FederatedOrganizationIdentifier</th>
</tr>
<tr>
<td><b>  Get-FederatedOrganizationIdentifier | select AccountNameSpace,Domains,Enabled</b></td>
<td>
<div><b>Domains:</b><span style='color: $Script:tdExoFedOrgIdDomainsColor;'>$($Script:tdExoFedOrgIdDomains)</span></div>
<div><b>Enabled:</b><span style='color: $Script:tdExoFedOrgIdEnabledColor;'>$($Script:tdExoFedOrgIdEnabled)</span></div>
</td>
</tr>
"
    Write-FreeBusyHtmlReport
}
function SharingPolicyCheckHtml() {
    $script:html += "
<tr>
  <th ColSpan='2' style='color:white;'>Summary - Get-SharingPolicy</th>
</tr>
<tr>
  <td><b>  Get-SharingPolicy | select Domains,Enabled,Name,Identity</b></td>
  <td>
    <div><b>Exchange On Premises Sharing domains:</b></div>
    <div><b>Domain:</b>$($Script:SPOnprem.Domains.Domain[0])</div>
    <div><b>Action:</b>$($Script:SPOnprem.Domains.Actions[0])</div>
    <div><b>Domain:</b>$($Script:SPOnprem.Domains.Domain[1])</div>
    <div><b>Action:</b>$($Script:SPOnprem.Domains.Actions[1])</div>
    <div><p></p></div>
    <div><b>Exchange Online Sharing domains:</b></div>
    <div><b>Domain:</b>$($domain1[0])</div>
    <div><b>Action:</b>$( $domain1[1])</div>
    <div><b>Domain:</b>$($domain2[0])</div>
    <div><b>Action:</b>$( $domain2[1])</div>
    <div><p></p></div>
    <div><b>Sharing Policy - Exchange Online vs Exchange On Premise:</b></div>
    <div><span style='color: $Script:tdSharpingPolicyCheckColor;'>$($Script:tdSharpingPolicyCheck)</span></div>
  </td>
</tr>
"
    Write-FreeBusyHtmlReport
}
function ExoTestOrgRelCheckHtml() {
    $exoIdentity = $ExoOrgRel.Identity
    $exoOrgRelTarGetApplicationUri = $exoOrgRel.TarGetApplicationUri
    $exoOrgRelTarGetOWAUrl = $ExoOrgRel.TarGetOwAUrl
    $script:html += "
  <tr>
      <th ColSpan='2' style='color:white;'>Summary - Test-OrganizationRelationship</th>
  </tr>
  <tr>
      <td><b>  Test-OrganizationRelationship -Identity $exoIdentity -UserIdentity $Script:UserOnline</b></td>
  <td>"
    if ((![string]::IsNullOrWhitespace($exoOrgRelTarGetApplicationUri)) -and (![string]::IsNullOrWhitespace($exoOrgRelTarGetOWAUrl))) {
        $i = 2
        while ($i -lt $ExoTestOrgRel.Length) {
            $element = $ExoTestOrgRel[$i]
            $aux = "0"
            if ($element -like "*RESULT:*" -and $aux -like "0") {
                $el = $element.TrimStart()
                if ($element -like "*Success.*") {
                    $Script:html += "
              <div> <b> $ExoTestOrgRelStep </b> <span style='color:green'> $el</span>"
                    $aux = "1"
                } elseif ($element -like "*Error*" -or $element -like "*Unable*") {
                    $Script:html += "
              <div> <b> $ExoTestOrgRelStep </b> <span style='color:red'> $el</span>"
                    $aux = "1"
                }
            } elseif ($aux -like "0" ) {
                if ($element -like "*STEP*" -or $element -like "*Complete*") {
                    $Script:html += "
              <p></p>
              <div> <b> $ExoTestOrgRelStep </b> <span style='color:black'> $element</span></div>"
                    $aux = "1"
                } else {
                    $ID = $element.ID
                    $Status = $element.Status
                    $Description = $element.Description
                    if (![string]::IsNullOrWhitespace($ID)) {
                        $Script:html += "<div> <b>ID: </b> <span style='color:black'> $ID</span></div>"
                        if ($Status -like "*Success*") {
                            $Script:html += "<div> <b>Status:</b> <span style='color:green'> $Status</span></div>"
                        }

                        if ($status -like "*error*") {
                            $Script:html += "<div> <b>Status:</b> <span style='color:red'> $Status</span></div>"
                        }

                        $Script:html += "<div> <b>Description: </b> <span style='color:black'> $Description</span></div>
                  <div><span style='color:blue'>Note: Test-Organization Relationship fails on Step 3 with error MismatchedFederation if Hybrid Agent is in use</span></div>"
                    }
                    #$element
                    $aux = "1"
                }
            }
            $i++
        }
    }

    elseif ((([string]::IsNullOrWhitespace($exoOrgRelTarGetApplicationUri)) -and ([string]::IsNullOrWhitespace($exoOrgRelTarGetOWAUrl)))) {
        $Script:html += "
  <div> <span style='color:red'> Exchange Online Test-OrganizationRelationship cannot be run if the Organization Relationship TarGetApplicationUri and TarGetOwAUrl are not set</span>"
    } elseif ((([string]::IsNullOrWhitespace($exoOrgRelTarGetApplicationUri)) )) {
        $Script:html += "
  <div> <span style='color:red'> Exchange Online Test-OrganizationRelationship cannot be run if the Organization Relationship TarGetApplicationUri is not set</span>"
    } elseif ((([string]::IsNullOrWhitespace($exoOrgRelTarGetApplicationUri)) )) {
        $Script:html += "
  <div> <span style='color:red'> Exchange Online Test-OrganizationRelationship cannot be run if the Organization Relationship TarGetApplicationUri is not set</span>"
    }
    $Script:html += "</td>
</tr>"
    Write-FreeBusyHtmlReport
}
#Exo Oauth Functions
function EXOIntraOrgConCheckHtml() {
    $script:html += "
<tr>
<th class='table-section' ColSpan='2' style='text-align:center; color:white;'><b>Exchange Online OAuth Configuration</b></th>
</tr>
<tr>
<th ColSpan='2' style=' color:white;'><b>Summary - Get-IntraOrganizationConnector</b></th>
</tr>
<tr>
<td><b>  Get-IntraOrganizationConnector | Select-Object TarGetAddressDomains, DiscoveryEndpoint, Enabled</b></td>
<td>
  <div><b>TarGet Address Domains:</b><span style='color:$Script:tdExoIntraOrgConTarGetAddressDomainsColor;'>' $($tdExoIntraOrgConTarGetAddressDomains)'</span></div>
  <div><b>DiscoveryEndpoint:</b><span style='color: $Script:tdExoIntraOrgConDiscoveryEndpointsColor;'>' $($Script:tdExoIntraOrgConDiscoveryEndpoints)'</span></div>
  <div><b>Enabled:</b><span style='color:$Script:tdExoIntraOrgConEnabledColor;'> $($Script:tdExoIntraOrgConEnabled)</span></div>
</td>
</tr>
"
    Write-FreeBusyHtmlReport
}
function EXOIntraOrgConfigCheckHtml() {
    $script:html += "
<tr>
  <th ColSpan='2' style='color:white;'><b>Summary - Get-IntraOrganizationConfiguration</b></th>
</tr>
<tr>
  <td><b>  Get-IntraOrganizationConfiguration | Select OnPremiseTarGetAddresses</b></td>
  <td>
    <div><b>OnPremiseTarGetAddresses:</b><span style='color: $Script:tdExoIntraOrgConfigOnPremiseTarGetAddressesColor;'>$($Script:tdExoIntraOrgConfigOnPremiseTarGetAddresses)</span></div>
  </td>
</tr>
"
    Write-FreeBusyHtmlReport
}
function EXOAuthServerCheckHtml() {
    $script:html += "
<tr>
<th ColSpan='2' style='color:white;'>Summary - Get-AuthServer</th>
</tr>
<tr>
<td><b>  Get-AuthServer -Identity 00000001-0000-0000-c000-000000000000 | select name,IssuerIdentifier,enabled</b></td>
<td>
<div><b>Name:</b><span style='color: $Script:tdExoAuthServerNameColor;'>$($Script:tdExoAuthServerName)</span></div>
<div><b>IssuerIdentifier:</b><span style='color: $Script:tdExoAuthServerIssuerIdentifierColor;'>$($Script:tdExoAuthServerIssuerIdentifier)</span></div>
<div><b>Enabled:</b><span style='color: $Script:tdExoAuthServerEnabledColor;'>$($Script:tdExoAuthServerEnabled)</span></div>
</td>
</tr>
"
    Write-FreeBusyHtmlReport
}
function ExoTestOAuthCheckHtml() {
    $script:html += "
<tr>
  <th ColSpan='2' style='color:white;'><b>Summary - Test-OAuthConnectivity</b></th>
</tr>
<tr>
  <td><b>  Test-OAuthConnectivity -Service EWS -TarGetUri $($Script:ExchangeOnPremEWS) -Mailbox $Script:UserOnline </b></td>
  <td>
    <div><b>Result:</b><span style='color:$Script:tdOAuthConnectivityResultTypeColor;'>$($tdOAuthConnectivityResultType)</span></div>
  </td>
</tr>
"
    Write-FreeBusyHtmlReport
}
function lookupMethodDAuthHtml() {
    $Script:html += "
                    <div class='method-heading'>
                      <h3>Intra Organization Connector Enabled: <b>True</b></h3>
                      <p> <span style='color: green; font-wight: 550; padding-left:2%; '>Checking DAuth only as -Auth DAuth option was selected</span></p>
                    </div>
                    <div class='method-help'>
                      <ul>
                        <li>
                          This script can be run using the <b>-Auth OAuth</b> parameter to Check for DAuth configurations only.
                          <br />
                          <span style='padding-left: 2%;'>
                            <br />
                            <b>Example:</b> ./FreeBusyChecker.ps1 -Auth OAuth
                          </span>
                        </li>
                        <br />
                        <li>
                          This script can be run using the <b>-Auth All</b> parameter to Check for both OAuth and DAuth configurations.
                          <br />
                          <span style='padding-left: 2%;'>
                            <br />
                            <b>Example:</b> ./FreeBusyChecker.ps1 -Auth All
                          </span>
                        </li>
                      </ul>
                    </div>
"
    Write-FreeBusyHtmlReport
}
function lookupMethodOauthHtml() {
    $Script:html += "
  <div class='method-heading'>
    <h3>Intra Organization Connector Enabled: <b>True</b></h3>
    <p> <span style='color: green; font-wight: 550; padding-left:2%; '>Checking OAuth only as Free Busy Lookup is done using OAuth when the Intra Organization Connector is Enabled</span></p>
  </div>
  <div class='method-help'>
    <ul>
      <li>
        This script can be run using the <b>-Auth DAuth</b> parameter to Check for DAuth configurations only.
        <br />
        <span style='padding-left: 2%;'>
          <br />
          <b>Example:</b> ./FreeBusyChecker.ps1 -Auth DAuth
        </span>
      </li>
      <br />
      <li>
        This script can be run using the <b>-Auth All</b> parameter to Check for both OAuth and DAuth configurations.
        <br />
        <span style='padding-left: 2%;'>
          <br />
          <b>Example:</b> ./FreeBusyChecker.ps1 -Auth All
        </span>
      </li>
    </ul>
  </div>
"
    Write-FreeBusyHtmlReport
}
function lookupMethodCheckAllHtml() {
    $Script:Auth = ""
    Write-Host -ForegroundColor White "    -> Free Busy Lookup is done using OAuth when the Intra Organization Connector is Enabled"
    Write-Host -ForegroundColor White "    -> Checking both OAuth and DAuth as -Auth All option was selected"
    $Script:html += "
              <div class='method-heading'>
                <h3>Intra Organization Connector Enabled: <b>True</b></h3>
                <p> <span style='color: green; font-wight: 550; padding-left:2%; '>Checking both OAuth and DAuth as -Auth All option was selected</span></p>
              </div>
              <div class='method-help'>
                <ul>
                  <li>
                    This script can be run using the <b>-Auth DAuth</b> parameter to Check for DAuth configurations only.
                    <br />
                    <span style='padding-left: 2%;'>
                      <br />
                      <b>Example:</b> ./FreeBusyChecker.ps1 -Auth DAuth
                    </span>
                  </li>
                  <br />
                  <li>
                    This script can be run using the <b>-Auth All</b> parameter to Check for both OAuth and DAuth configurations.
                    <br />
                    <span style='padding-left: 2%;'>
                      <br />
                      <b>Example:</b> ./FreeBusyChecker.ps1 -Auth All
                    </span>
                  </li>
                </ul>
              </div>
"
    Write-FreeBusyHtmlReport
}
function lookupMethodDAuthOauthDisabledHtml() {
    $Script:html += "
                    <div class='method-heading'>
                      <h3>Intra Organization Connector Enabled: <b>False</b></h3>
                      <p> <span style='color: green; font-wight: 550; padding-left:2%; '>Checking DAuth as OAuth is not Enabled</span></p>
                    </div>
                    <div class='method-help'>
                      <ul>
                        <li>
                          This script can be run using the <b>-Auth OAuth</b> parameter to Check for OAuth configurations only.
                          <br />
                          <span style='padding-left: 2%;'>
                            <br />
                            <b>Example:</b> ./FreeBusyChecker.ps1 -Auth OAuth
                          </span>
                        </li>
                        <br />
                        <li>
                          This script can be run using the <b>-Auth All</b> parameter to Check for both OAuth and DAuth configurations.
                          <br />
                          <span style='padding-left: 2%;'>
                            <br />
                            <b>Example:</b> ./FreeBusyChecker.ps1 -Auth All
                          </span>
                        </li>
                      </ul>
                    </div>
"
    Write-FreeBusyHtmlReport
}
function lookupMethodOauthOauthDisabledHtml() {
    $Script:html += "
                  <div class='method-heading'>
                    <h3>Intra Organization Connector Enabled: <b>False</b></h3>
                    <p> <span style='color: green; font-wight: 550; padding-left:2%; '>Checking OAuth as -Auth OAuth parameter was selected</span></p>
                  </div>
                  <div class='method-help'>
                    <ul>
                      <li>
                        This script can be run using the <b>-Auth All</b> parameter to Check for both OAuth and DAuth configurations.
                        <br />
                        <span style='padding-left: 2%;'>
                          <br />
                          <b>Example:</b> ./FreeBusyChecker.ps1 -Auth All
                        </span>
                      </li>
                    </ul>
                  </div>
"
    Write-FreeBusyHtmlReport
}
function lookupMethodAllOauthDisabledHtml() {
    $Script:html += "
              <div class='method-heading'>
                <h3>Intra Organization Connector Enabled: <b>False</b></h3>
                <p> <span style='color: green; font-wight: 550; padding-left:2%; '>Checking both for OAuth and DAuth as -Auth All parameter was selected</span></p>
              </div>
              <div class='method-help'>
                <ul>
                  <li>
                    This script can be run using the <b>-Auth OAuth</b> parameter to Check for OAuth only.
                    <br />
                    <span style='padding-left: 2%;'>
                      <br />
                      <b>Example:</b> ./FreeBusyChecker.ps1 -Auth OAuth
                    </span>
                  </li>
                </ul>
              </div>
"
    Write-FreeBusyHtmlReport
}
function exoHeaderHtml() {
    if ($Script:htmlTableOpen) {
        $Script:html += "</table>"
    }
    $Script:htmlTableOpen = $true
    $Script:html += "
  <div class='Black'><p></p></div>
  <div class='Black'><p></p></div>
         <div class='Black'><h2><b>`n Exchange Online Free Busy Configuration: `n</b></h2></div>
         <div class='Black'><p></p></div>
         <div class='Black'><p></p></div>
 <table style='width:100%; margin-top:30px;'>
<colgroup><col class='command-column'><col class='result-column'></colgroup>
"
    Write-FreeBusyHtmlReport
}
