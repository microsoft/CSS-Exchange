# Transport Retry Configuration Check

This check verifies that the Transport Service retry configuration and max outbound connections per domain are set to the recommended values. When these values are not set to the recommended values, it can cause mail queueing or longer than expected delivery time when a transient failure occurs.

This check validates the following settings in the `Get-TransportService` configuration:

- `MaxPerDomainOutboundConnections` is set to 40 or greater
- `MessageRetryInterval` is set to 5 minutes or less

## MaxPerDomainOutboundConnections

This setting controls the number of outbound connections that can be open for a single destination domain at one time. When this setting is too low and connections are exhausted, it will cause mail to queue up in the transport service and cause delays in mail delivery. This is most noticeable when mail is sent to a single destination such as in an Office 365 hybrid environment.

## MessageRetryInterval

This setting controls the interval at which the transport service will retry sending a message that has failed to send due to a transient error. When this setting is too high, it can cause mail to queue up unnecessarily. Retrying sooner in most cases will allow the message to be delivered in a timely manner.

## Included in HTML Report?

Yes

## Additional resources

[Email messages are stuck in Exchange Server queues for several minutes](https://aka.ms/TransportRetryConfig)
