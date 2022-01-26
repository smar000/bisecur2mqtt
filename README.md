
An MQTT wrapper around the python based [BiSecur Gateway library](https://github.com/skelsec/pysecur3) developed by @skelsec for Hormann Bisecure Gateway devices. 

**NOTES**:
* The MQTT wrapper only supports the Hormann's garage *door* devices and mainly just the basic door related commands (up, down, impulse, stop, partial, light). 

* Each such command that is to be sent through this wrapper (except `stop`) *MUST* be defined in the Bisecur mobile phone app first otherwise port errors will occur. As a minimum, the `impulse` channel is required, as this is also used to get the door position data.

* The `user` for the wrapper should also be a unique user used just for this wrapper (i.e. it should not be the one used for the mobile phone app etc) and must have permissions for the device. Also note that the ports must be manually specified in the config file (these can be obtained by sending a `get_ports` command).

* The default topic subscribed by the script for receiving commands is `bisecur2mqtt/send_command/command`.

* The wrapper also publishes a basic Homeassistant 'cover' device for auto-discovery. This may or may not work fully as it has not yet been tested on Homeassistant (it seems to be working on openHAB).

This wrapper was built entirely for my personal use, and it is now at a level that it serves my purpose. As such, it is unlikely to be developed much further, though PRs and bug fixes are always welcome. 

