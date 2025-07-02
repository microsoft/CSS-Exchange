# Exchange Server Computer Membership

### Description:

Checks for the computer object to be members of the `Exchange Trusted Subsystem` and `Exchange Servers` security groups by default. It will also make sure the default local system account has the `Exchange Trusted Subsystem` a member of it as well in order to have the correct access to local system files.

This check is done by using an LDAP query to find the computer object in AD and getting the `memberOf` properties.

If an issue is detected, the group will display with where the problem is located. Either `Local System Membership` if the group isn't part of the local system account or `AD Group Membership` if the computer object isn't a member of the group provided.

If you see an output of:

    Exchange Server Membership: Failed
            Unable to determine Local System Membership as the results were blank.

This can have multiple meanings.

1. Ambiguous: The command Get-LocalGroupMember failed to run successfully.
2. Literal: That there is a group membership issue.

Confirm which one of the two is the problem by reviewing local group membership. The `Administrators` group should have members which include: `Domain Admins`, `Exchange Trusted Subsystem`, and `Organization Management`.

If you see an output of:

    Exchange Server Membership: Failed
            Unable to determine AD Group Membership as the results were blank.

This can have multiple meanings.

1. Ambiguous: The LDAP query failed to run successfully.
2. Literal: That there is a group membership issue.

Confirm which one of the two is the problem by reviewing what groups the Server is a member of. The server should be a member of `Exchange Trusted Subsystem`, and `Exchange Servers`.

**Included in HTML Report?**

Yes
