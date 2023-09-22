# ReplayQueueDatabases

Download the latest release: [ReplayQueueDatabases.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/ReplayQueueDatabases.ps1)

When Transport crashes, in some scenarios it will move the current queue
database to Messaging.old-<date> and create a new empty database. The old
database is usually not needed, unless shadow redundancy was failing. In
that case, it can be useful to drain the old queue file to recover those
messages.

This script automates the process of replaying many old queue files created
by a series of crashes.

## Syntax

```powershell
ReplayQueueDatabases.ps1
  [-MaxAgeInDays <int>]
  [-RemoveDeliveryDelayedMessages]
```

## Parameters

    -MaxAgeInDays <Int32>
        Only replay queue databases newer than this date

        Required?                    false
        Position?                    1
        Default value                7

    -RemoveDeliveryDelayedMessages [<SwitchParameter>]
        Attempt to remove delivery delay notifications so user mailboxes do not fill up with these while we replay old messages

        Required?                    false
        Position?                    named
        Default value                False

## Usage

The script must be run from Exchange Management Shell locally on the server where queue databases
are being replayed. Preliminary steps before running this script:

* Move all active Mailbox Databases to another DAG member
* Run this command from Exchange Management Shell:
`Set-MailboxServer $env:ComputerName -DatabaseCopyAutoActivationPolicy Blocked`

When the script is run, it takes the following actions.

* Read the QueueDatabasePath and QueueDatabaseLoggingPath from the EdgeTransport.exe.config file. If these do not match, the script exits. That type of configuration is not yet supported by this script.
* Search the QueueDatabasePath for any folders with names matching Message.old-*.
* Parse the date string in the folder name to determine if this folder is under the MaxAgeInDays.
* Any folders _over_ the MaxAgeInDays are moved to the ReplaySkipped folder in the QueueDatabasePath.
* The EdgeTransport.exe.config is copied to EdgeTransport.exe.config.before-replay.

* Begin looping over the folders that were under MaxAgeInDays, starting with the most deeply nested folder.
* Check if the HubTransport component is in Draining state, and switch it to Draining if it is not.
* Stop the Transport services (MSExchangeTransport and MSExchangeFrontEndTransport).
* Move the current folder to be replayed to OldReplayQueue in the QueueDatabasePath.
* Start the Transport services.
* Check every 5 seconds if the queues clear. While waiting, run Remove-Message once a minute to remove any "Delivery Delayed" messages.
* Once queues are cleared, stop the transport services.
* Move OldQueueReplay to a folder inside of Replayed in the QueueDatabasePath, named Replayed-\<original date on the folder\>.
* Continue to the next folder.

* When finished with all the folders, stop the Transport services.
* Overwrite EdgeTransport.exe.config with EdgeTransport.exe.config.before-replay.
* Start the Transport services.
* Notify the user that they must run the command to take the HubTransport component out of the Draining state when ready.

Note that when the script is run without -Confirm:$false, it will prompt for nearly every step of this process. This is
probably the best approach for most scenarios, so that each step of the script is visible and understood by the user.
"Yes to All" can be used to remove most of the prompting within the script. However, even with "Yes to All", prompts to
start and stop services between replays of each database will occur.

If there are many databases to replay, -Confirm:$false can be used to remove all prompting.

## Cleanup

If the script fails out or is terminated in the middle, the following steps may be needed in
order to run the script again and/or return the environment to a normal state.

* OldQueueReplay may have been left in place. If it is not clear whether this database was already replayed,
  Transport services should be started while QueueDatabasePath and QueueDatabaseLoggingPath in EdgeTransport.exe.config
  still point to OldQueueReplay. Once the queues have drained, Transport can be stopped, and OldQueueReplay can be moved to
  the Replayed folder.
* The EdgeTransport.exe.config may be left pointing to OldQueueReplay. To fix it, replace EdgeTransport.exe.config
  with the EdgeTransport.exe.config.before-replay, which was the backup of the file prior to any changes.
* MSExchangeTransport and MSExchangeFrontEndTransport may need to be started.
* The HubTransport component must be set back to Active.
