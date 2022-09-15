# TLS Configuration Check

We check and validate Exchange servers TLS 1.0 - 1.2 configuration. We can detect mismatches in TLS versions for client and server. This is important because Exchange can be both a client and a server.

We also check for the SystemDefaultTlsVersions registry value which controls if .NET Framework will inherit its defaults from the Windows Schannel DisabledByDefault registry values or not.

An invalid TLS configuration can cause issues within Exchange for communication.

Only the values 0 or 1 are accepted and determined to be properly configured. The reason being is this is how our documentation provides to configure the value only and it then depends on how the code reads the value from the registry interpret the value.

By not having the registry value defined, different versions of .NET Frameworks for what the code is compiled for will treat TLS options differently. Therefore, we throw an error if the key isn't defined and action should be taken to correct this as soon as possible.

The `Configuration` result can provide a value of `Enabled`, `Disabled`, `Half Disabled`, or `Misconfigured`. They are defined by the following conditions:

Value | Definition
------|-----------
Enabled | Client and Server Enabled values are set to 1 and DisabledByDefault is set to 0 on the TLS Version.
Disabled | Client and Server Enabled values are set to 0 and DisabledByDefault is set to 1 on the TLS Version.
Half Disabled | Client and Server Enabled values are set to either 0 or 1 and DisabledByDefault is set to the opposite where the value doesn't equal Enabled or Disabled.<br>This is not a supported configuration as it doesn't follow the documentation that we have provided.
Misconfigured | When either the Enabled or the DisabledByDefault values do not match between the Client and Server of that TLS Version.<br>Exchange can be a Client and a Server and this will cause problems and needs to be addressed ASAP.

The location where we are checking for the TLS values are here:

`SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client`
`SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server`
`SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client`
`SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server`
`SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client`
`SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server`

At each location, we are looking at the value of `Enabled` and `DisabledByDefault`. If the key isn't present, `Enabled` is set to `true` and `DisabledByDefault` is set to `false`.

The location for the .NET Framework TLS related settings are located here:

`SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319`
`SOFTWARE\Microsoft\.NETFramework\v4.0.30319`
`SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727`
`SOFTWARE\Microsoft\.NETFramework\v2.0.50727`

At each location, we are looking at the value of `SystemDefaultTlsVersions` and `SchUseStrongCrypto`. If the key isn't present, both are set to `false`.

**Included in HTML Report?**

Yes

**Additional resources:**

[Exchange Server TLS configuration best practices](https://aka.ms/HC-TLSGuide)

[Exchange Server TLS guidance, part 1: Getting Ready for TLS 1.2](https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Exchange-Server-TLS-guidance-part-1-Getting-Ready-for-TLS-1-2/ba-p/607649)

[Exchange Server TLS guidance Part 2: Enabling TLS 1.2 and Identifying Clients Not Using It](https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Exchange-Server-TLS-guidance-Part-2-Enabling-TLS-1-2-and/ba-p/607761)

[Exchange Server TLS guidance Part 3: Turning Off TLS 1.0/1.1](https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Exchange-Server-TLS-guidance-Part-3-Turning-Off-TLS-1-0-1-1/ba-p/607898)

