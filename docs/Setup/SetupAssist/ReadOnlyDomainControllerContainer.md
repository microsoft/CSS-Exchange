# Read Only Domain Controller - Domain Controllers OU

A Read Only Domain Controller appears to be in the container other than CN=Domain Controllers.
This will cause setup to fail if we attempt to domain prep that domain.
The path to the RODC must be CN=DCName,CN=Domain Controllers....
