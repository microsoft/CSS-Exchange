# Exchange Server Maintenance Check

**Description:**

We validate the Maintenance State for the Exchange server. We run the following checks:

- We query the server component state by running `Get-ServerComponentState`
- We query cluster node information by running `Get-ClusterNode`
- We then check for each component if `Component.State` is not `Active`
- If this is the case, we query the `Component.LocalStates` and `Component.RemoteStates`
- We validate if both states `LocalStates` & `RemoteStates` are the same
- We add the information, if `LocalStates` & `RemoteStates` are different

We show a green information `Server is not in Maintenance Mode` if the server is not in maintenance mode.

We display a yellow warning `Exchange Server Maintenance` if components in maintenance state are detected. We also show additional information about the `Database Copy Maintenance` and `Cluster Node` state.

**Included in HTML Report?**

Yes

**Additional resources:**

[Determine the requestor that changed Server component state](https://docs.microsoft.com/en-us/exchange/troubleshoot/administration/requestor-changed-server-component)

