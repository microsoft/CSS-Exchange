# Exchange IIS Information

## Description

We show some general information about your Exchange Server from the IIS perspective. This goes into detail to make sure that Sites and App Pools are started, which might not be easy to spot at a quick look a the server. It will also call out some common misconfiguration issues, that will cause problems with client connectivity.


## Sites

This provides the sites that we found and the following information:

- State (Started or Stopped)
- HSTS Enabled (Only supported on `Default Web Site`)
- Protocol - Binding - Certificate ( Which protocol is binding to which port and with what certificate if any)

**NOTE:** HSTS if enabled on the Back End will call out an issue.

## App Pools

This provides the application pools on the server with the following information:

- State (Started or Stopped)
- GCServerEnabled (Garbage Collection Server Enabled - Depends on the RAM on the server if this should be enabled or not on the server. If it should be, Health Checker should call it out.)
- RestartConditionSet ( If there is an IIS setting that will automatically restart the App Pool. This is not recommended and will cause issues with client connectivity )

## Virtual Directory Locations

This provides the different locations that you use for different connection endpoints with the following information:

- Extended Protection ( The current value )
- Ssl Flags ( If enabled and/or Cert based )
- IP Filtering Enabled ( If any IP filtering is enabled )
- URL Rewrite ( Names of each rule applied at the location )
- Authentication ( Provides each type of authentication that is enabled for the location. If anonymous `default setting` will be provided if that is enabled Out of the Box on the server )

**NOTE:** For each of the URL Rewrite rules, we will display additional information about the rule to let you know what it is doing. It is also recommended to remove any mitigation rules that you might have applied if you have the security fix installed on the server.

### Included in HTML Report?

Yes
