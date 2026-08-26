# Trusted Root Certificates Check

**Description:**

This check validates whether the automatic updating of Windows root certificates has been disabled via Group Policy.

Registry: `HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot\DisableRootAutoUpdate`

When this value is set to `1`, Windows will not automatically download and install trusted root certificates from Windows Update. This means the server will not receive new root certificate authorities or updates to existing ones.

If root certificates used by Azure and Microsoft 365 services are missing or outdated on the Exchange server, this can cause connectivity issues to Azure or Exchange Online services.

When automatic root certificate updates are disabled, administrators must ensure that the required root and intermediate certificates are manually kept up to date. The list of required certificates can be found in the Azure Certificate Authority Details documentation.

**Important:** Starting March 15, 2026, Exchange Online will begin using the DigiCert Global Root G2 certificate authority. Servers that have automatic root certificate updates disabled and do not have this root CA installed may experience email delivery failures or other connectivity issues with Exchange Online. For details, see the announcement linked below.

**Included in HTML Report?**

Yes

**Additional resources:**

[Trust DigiCert Global Root G2 certificate authority to avoid Exchange Online email delivery issues](https://techcommunity.microsoft.com/blog/exchange/trust-digicert-global-root-g2-certificate-authority-to-avoid-exchange-online-ema/4488311)

[Azure Certificate Authority Details - Root and Intermediate CA Chains](https://learn.microsoft.com/en-us/azure/security/fundamentals/azure-certificate-authority-details?tabs=certificate-authority-chains)

[Configure Trusted Roots and Disallowed Certificates](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/configure-trusted-roots-disallowed-certificates)
