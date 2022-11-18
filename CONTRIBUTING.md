# Notes for contributors

Install the git hooks with copy_git_hooks.sh, or just copy them from .git_hooks to .git/hooks manually.

Some of the automated tests require an MQTT broker to be running.
I recommend using mosquitto since this repository contains a test config for mosquitto, but if you want to use another broker I would ask that you add a config file for it so others can use it too.
To make use of the config file, run **mosquitto -c test_data/mosquitto.conf** from the mqtt_vault directory.

All included SSL certificates and private keys use *test* as the password.
If you introduce more certs, please keep using *test* as the password.
The same goes for MQTT user passwords.
