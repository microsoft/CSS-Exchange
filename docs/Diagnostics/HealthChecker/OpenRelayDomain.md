# Open Relay Domain

**Description:**

We show a warning if we weren't able to run `Get-AcceptedDomain` and provide an `unknown` status. If we determine that an Open Relay Domain is set on the environment, we will throw an error in the results and provide which accepted domain ID is set with this. It is recommended to have an anonymous relay and scope down the receive connector for who can use it. Otherwise, you are allowing anybody to use your environment to send mail anywhere.

**NOTE:** After installing the September 2021 CUs for Exchange 2016/2019, you can see crashes occur on your system for the transport services that look like this:

```
Log Name:      Application
Source:        MSExchange Common
Date:          12/3/2021 12:40:35 PM
Event ID:      4999
Task Category: General
Level:         Error
Keywords:      Classic
User:          N/A
Computer:      Contoso-E19A.Contoso.com
Description:
Watson report about to be sent for process id: 10072, with parameters: E12IIS, c-RTL-AMD64, 15.02.0986.005, MSExchangeDelivery, M.Exchange.Transport, M.E.T.AcceptedDomainTable..ctor, System.FormatException, 28d7-DumpTidSet, 15.02.0986.005.
ErrorReportingEnabled: False
```

This is caused by having an Internal Relay with an Accepted Domain of *. This is not a recommended configuration.

**Included in HTML Report?**

Yes

**Additional resources:**

[Allow anonymous relay on Exchange servers](https://docs.microsoft.com/en-us/Exchange/mail-flow/connectors/allow-anonymous-relay?view=exchserver-2019)

