# Certificate Check

This check retrieves all certificates from the Exchange server by using the `Get-ExchangeCertificate` cmdlet. We display the following information:

- FriendlyName
- Thumbprint
- Lifetime in days
- Key size
- Signature algorithm
- Signature hash algorithm
- Bound to services
- Current Auth Certificate
- SAN Certificate
- Namespaces

We also perform the following checks:

- Certificate lifetime check:
    - We show a green output, if the certificate is valid for 60 or more days.
    - We show a yellow warning, if the certificate lifetime is between 30 and 59 days.
    - We show a red warning if the lifetime is < 30 days.

- Weak key size check:
    - We show a red warning, if the key size is lower than 2048 bit.

- Weak hash algorithm check:
    - We show a yellow warning if the hash algorithm used to sign a certificate is weak.

- Valid Auth certificate check:
    - We check if the certificate which is set as current Auth certificate is available on the server.

**Included in HTML Report?**

Yes

