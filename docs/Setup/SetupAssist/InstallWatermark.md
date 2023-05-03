# Install Watermark

After a failed install attempt of Exchange, we can leave behind a watermark that then prevents you from trying to run setup again when trying use unattended mode. To get around this issue, run Setup.exe from the GUI and not the command line. From the GUI, it is able to detect that we had a watermark and tries to pick up where we left off. However, unattended mode fails in the prerequisites check section prior to running and the GUI skips over this section.

!!! warning "Warning"

      Do **NOT** remove the watermark from the registry as you will run into more setup issues trying to run steps the server already completed. Run setup from the GUI to allow setup to pick up where the watermark is set at.
