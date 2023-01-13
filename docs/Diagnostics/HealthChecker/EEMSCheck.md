# Exchange Emergency Mitigation Service Check

**Description:**

The `Exchange Emergency Mitigation Server` also known as `EEMS` or `EM` was introduced with the `Exchange Server 2019 Cumulative Update 11` and `Exchange Server 2016 Cumulative Update 22`.

The Exchange Emergency Mitigation service helps to keep your Exchange Servers secure by applying mitigations to address any potential threats against your servers. It uses the cloud-based `Office Config Service (OCS)` to check for and download available mitigations and to send diagnostic data to Microsoft.

The EM service runs as a Windows service on an Exchange Mailbox server. The EM service will be installed automatically on servers with the Mailbox role. The EM service will not be installed on Edge Transport servers.

The use of the EM service is optional. If you do not want Microsoft to automatically apply mitigations to your Exchange servers, you can disable the feature.

This check performs the following testings to highlight the configuration state of the EEMS:

- Configuration Check
    - Shows if the EEMS is enabled or not on Organizational level
    - Shows if the EEMS is enabled or not on Server level

- Windows Service Check
    - `MSExchangeMitigation` Windows service startup type should be: `Automatic`
    - `MSExchangeMitigation` Windows service status should be: `Running`

- Pattern Service Check
    - We validate if we can reach the OCS which is used to serve the latest mitigations
    - OCS Mitigation Service url: `https://officeclient.microsoft.com/GetExchangeMitigations`

- Mitigations Check
    - Shows which mitigations are currently being applied
    - Shows which mitigations are currently being blocked

- Diagnostic Data Check
    - Shows if the service is configured to provide diagnostic data to Microsoft or not

**Included in HTML Report?**

Yes

**Additional resources:**

[New security feature in September 2021 Cumulative Update for Exchange Server](https://techcommunity.microsoft.com/t5/exchange-team-blog/new-security-feature-in-september-2021-cumulative-update-for/ba-p/2783155)

[Released: September 2021 Quarterly Exchange Updates](https://techcommunity.microsoft.com/t5/exchange-team-blog/released-september-2021-quarterly-exchange-updates/ba-p/2779883)

[Addressing Your Feedback on the Exchange Emergency Mitigation Service](https://techcommunity.microsoft.com/t5/exchange-team-blog/addressing-your-feedback-on-the-exchange-emergency-mitigation/ba-p/2796190)

[Exchange Emergency Mitigation (EM) service](https://docs.microsoft.com/exchange/exchange-emergency-mitigation-service?view=exchserver-2019)

[Mitigations Cloud endpoint is not reachable](https://docs.microsoft.com/exchange/plan-and-deploy/deployment-ref/ms-exch-setupreadiness-MitigationsCloudEndpointUnreachable?view=exchserver-2019)

